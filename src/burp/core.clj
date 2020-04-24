(ns burp.core
  (:require [nrepl.server :refer [start-server stop-server]]
            [cemerick.pomegranate :refer [add-dependencies]]
            [camel-snake-kebab.core :as csk]
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

(defmacro enum-filed->map
  "`class`中的静态enum字段转换到invert map"
  [class prefix]
  (let [methods (get-classinfo (eval class))
        static-fields (->> methods
                           (filter :type)
                           (filter #(and ((:flags %) :static)
                                         (str/starts-with? (name (:name %))
                                                           (name prefix))))
                           (map (comp str :name)))
        start-pos (dec (count (name prefix)))
        get-field-kv (fn [field]
                       [(-> (symbol (name class) field)
                            eval)
                        (-> (subs field start-pos)
                            (csk/->kebab-case-keyword))])]
    (->> static-fields
         (map get-field-kv)
         (into {}))))

(def param-type (enum-filed->map IParameter PARAM_))
(def request-content-type (enum-filed->map IRequestInfo CONTENT_TYPE_))
(def intercept-action (enum-filed->map IInterceptedProxyMessage ACTION_))

(defn parse-param [^IParameter param]
  {:name (.getName param)
   :type (-> (.getType param)
             param-type)
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
                     request-content-type)
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

(.registerProxyListener (get-extender) (proxy-proc))

