(ns burp.core
  (:require [nrepl.server :refer [start-server stop-server]]
            [cemerick.pomegranate :refer [add-dependencies]]
            [seesaw.core :as gui]
            [camel-snake-kebab.core :as csk]
            [buddy.core.bytes :as bytes]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as base64]
            [clojure.java.browse :refer [browse-url]]
            [clojure.string :as str])
  (:import [burp
            IBurpExtender
            IBurpExtenderCallbacks
            IProxyListener
            IInterceptedProxyMessage
            IHttpRequestResponse
            IExtensionStateListener
            IRequestInfo
            IResponseInfo
            IParameter
            ICookie
            IContextMenuInvocation
            IContextMenuFactory
            ]
           [java.io PrintWriter]))

;;;;;;;;;;;;;;;;;;;;; extension reg
(def state (atom nil))

(defn log [s]
  (.printOutput (:extender @state) s))

(defn nrepl-handler []
  (require 'cider.nrepl)
  (ns-resolve 'cider.nrepl 'cider-nrepl-handler))

(defn extension-unload []
  (reify IExtensionStateListener
    (extensionUnloaded [_]
      (log "stopping nrepl server.")
      (stop-server (:nrepl-server @state))
      (log "extension unload."))))

(defn register
  "注册回调"
  [cbs]
  (.setExtensionName cbs "clojure nrepl")
  (let [stdout (-> (.getStdout cbs)
                   (PrintWriter. true))
        repl-port 22233
        nrepl-server (start-server :bind "0.0.0.0"
                                   :port repl-port
                                   :handler (nrepl-handler))]
    (swap! state assoc
           :extender cbs
           :nrepl-server nrepl-server)
    (.registerExtensionStateListener cbs (extension-unload))
    (.println stdout (str "nrepl started at" repl-port))))

;;;;;;;;;;;;;;;;;;;;;;;;;;; helpers
(def default-repo (merge cemerick.pomegranate.aether/maven-central
                         {"clojars" "https://clojars.org/repo"}))
(defn add-dep
  [libs & {:keys [repos]
           :or {repos default-repo}}]
  (add-dependencies :coordinates libs :repositories repos))


(require '[clojure.reflect :as reflect])
(require '[clojure.pprint :as pp])

(defn get-classinfo
  [class]
  (->> (reflect/reflect class)
       :members
       (sort-by :name)))

(defn print-classinfo
  [class]
  (->> (get-classinfo class)
       (pp/print-table [:name :flags :parameter-types :return-type])))

(defn get-extender []
  (:extender @state))

(defn get-helper []
  (-> (get-extender)
      .getHelpers))

(defmacro def-enum-fileds-map
  "定义`class`中的静态enum字段"
  [map-name class prefix]
  (let [methods (get-classinfo (eval class))
        static-fields (->> methods
                           (filter :type)
                           (filter #(and ((:flags %) :static)
                                         (str/starts-with? (name (:name %))
                                                           (name prefix))))
                           (map (comp str :name)))
        start-pos (dec (count (name prefix)))
        get-field-kv (fn [field]
                       [(-> (subs field start-pos)
                            (csk/->kebab-case-keyword))

                        (-> (symbol (name class) field)
                            eval)])
        field-map (->> static-fields
                       (map get-field-kv)
                       (into {}))
        inv-filed-map (clojure.set/map-invert field-map)
        inv-map-name (-> (name map-name)
                         (str "-inv")
                         symbol)]
    `(do
       (def ~map-name ~field-map)
       (def ~inv-map-name ~inv-filed-map))))

(def-enum-fileds-map param-type IParameter PARAM_)
(def-enum-fileds-map request-content-type IRequestInfo CONTENT_TYPE_)
(def-enum-fileds-map intercept-action IInterceptedProxyMessage ACTION_)
(def-enum-fileds-map menu-invocation-context IContextMenuInvocation CONTEXT_)

(defn parse-param [^IParameter param]
  {:name (.getName param)
   :type (-> (.getType param)
             param-type-inv)
   :value (.getValue param)})

(defn parse-cookie [^ICookie cookie]
  {:domain (.getDomain cookie)
   :expiration (.getExpiration cookie)
   :name (.getName cookie)
   :path (.getPath cookie)
   :value (.getValue cookie)})

(defn parse-request [^IRequestInfo req]
  {:method (.getMethod req)
   :content-type (-> (.getContentType req)
                     request-content-type-inv)
   :body-offset (.getBodyOffset req)
   :headers (.getHeaders req)
   :params (->> (.getParameters req)
                (map parse-param))
   :url (try (.getUrl req)
             (catch Exception _ nil))})

(defn analyze-request
  "分析请求"
  ([req]
   (-> (get-helper)
       (.analyzeRequest req)
       parse-request))
  ([http-service req]
   (-> (get-helper)
       (.analyzeRequest http-service req)
       parse-request)))


(defn analyze-response
  [resp]
  (let [resp-info (-> (get-helper)
                      (.analyzeResponse resp))]
    {:headers (.getHeaders resp-info)
     :state-mime-type (.getStatedMimeType resp-info)
     :status (.getStatusCode resp-info)
     :body-offset (.getBodyOffset resp-info)
     :cookies (->> (.getCookies resp-info)
                   (map parse-cookie))}))

(defn proxy-proc []
  (reify IProxyListener
    (processProxyMessage [this is-req msg]
      (when-not is-req
        (let [req-resp (.getMessageInfo msg)
              req (analyze-request req-resp)
              resp (-> (.getResponse req-resp)
                       analyze-response)]
          (log (str "request info:" req
                    "\n"
                    "response info:" resp))
          )))
    ))

(defn remove-all-proxy-listeners []
  (let [ext (get-extender)]
    (doseq [l (.getProxyListeners ext)]
      (.removeProxyListener ext l))))

(defn remove-all-context-menu []
  (let [ext (get-extender)]
    (doseq [f (.getContextMenuFactories ext)]
      (.removeContextMenuFactory ext f))))

(defn get-invocation-context
  [invocation]
  (-> (.getInvocationContext invocation)
      menu-invocation-context-inv))

(defn get-selected-text
  "获得选中的字符"
  [invocation]
  (when-let [sel (.getSelectionBounds invocation)]
    (when-let [msg (-> (.getSelectedMessages invocation)
                       first)]
      (let [data (if (#{:message-editor-request
                        :message-viewer-request}
                      (get-invocation-context invocation))
                   (.getRequest msg)
                   (.getResponse msg))
            [start end] sel]
        ;; (log (format "sel:[%d %d]" start end))
        (-> (bytes/slice data start end)
            (codecs/bytes->str))))))


(defn browse-cyber-chef
  [input]
  (->> (base64/encode input)
       (codecs/bytes->str)
       (str "https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=" )
       browse-url))

(defn cyber-chef-menu []
  (reify IContextMenuFactory
    (createMenuItems [this invocation]
      (let [menu-ctx (get-invocation-context invocation)]
        (log (str "2 add new context menu:" (type menu-ctx)
                  ":test " (type (#{:message-editor-request
                                    :message-editor-response
                                    :message-viewer-request
                                    :message-viewer-response} menu-ctx))))
        (if (#{:message-editor-request
               :message-editor-response
               :message-viewer-request
               :message-viewer-response} menu-ctx)
          (do (log "add menus")
              [(gui/menu-item :text "CyberChef Magic"
                              :listen [:action (fn [e]
                                                 (when-let [txt (get-selected-text invocation)]
                                                   (log (str "selected text:" txt))
                                                   (browse-cyber-chef txt)))])
               ])
          []
          )
        ))))

(comment

  (remove-all-proxy-listeners)

  (.registerProxyListener (get-extender) (proxy-proc))

  (.registerContextMenuFactory (get-extender) (cyber-chef-menu))

  (remove-all-context-menu)

  )

