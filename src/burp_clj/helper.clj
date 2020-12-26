(ns burp-clj.helper
  (:require [clojure.string :as str]
            [clojure.java.io :refer [as-url]]
            [burp-clj.extender :as extender]
            [taoensso.timbre :as log]
            [camel-snake-kebab.core :as csk]
            [burp-clj.i18n :as i18n]
            [burp-clj.state :as state]
            [burp-clj.utils :refer [def-enum-fileds-map]]
            [burp-clj.utils :as utils])
  (:refer-clojure :exclude [alert])
  (:import javax.swing.JTabbedPane
           [burp
            IBurpExtender
            IBurpExtenderCallbacks
            IProxyListener
            IInterceptedProxyMessage
            IHttpRequestResponse
            IExtensionStateListener
            IRequestInfo
            IResponseInfo
            IHttpService
            IParameter
            ICookie
            IMessageEditorController
            IContextMenuInvocation
            IContextMenuFactory]))

(defn find-burp-tab
  [ui-comp]
  (if (instance? JTabbedPane ui-comp)
    ui-comp
    (find-burp-tab (.getParent ui-comp))))

(defn set-burp-tab!
  [burp-tab]
  (swap! state/state assoc :burp-tab burp-tab))

(defn get-burp-tab
  []
  (some-> (get @state/state :burp-tab)
          deref))

(defn get-curr-burp-tab-title
  []
  (when-let [burp-tab (get-burp-tab)]
    (->> (.getSelectedIndex burp-tab)
         (.getTitleAt burp-tab))))

(defn set-burp-clj-view!
  [view]
  (swap! state/state assoc :burp-clj-view view)
  (set-burp-tab! (delay (find-burp-tab view))))

(defn get-burp-clj-view
  []
  (:burp-clj-view @state/state))

(defn switch-burp-tab
  [tab-title]
  (log/info "switch burp tab to:" tab-title)
  (when-let [burp-tab (get-burp-tab)]
    (let [max-idx (-> (.getTabCount burp-tab)
                      dec)]
      (loop [i 0]
        (if (= tab-title (.getTitleAt burp-tab i))
          (.setSelectedIndex burp-tab i)
          (when (< i max-idx)
            (recur (inc i)))))))
  (log/info "------> curr tab:" (get-curr-burp-tab-title)))

(defn switch-clojure-plugin-tab
  []
  (when-let [burp-tab (get-burp-tab)]
    (->> (get-burp-clj-view)
         (.setSelectedComponent burp-tab))))

(defn get-helper []
  (-> (extender/get)
      .getHelpers))

(defn cat-msgs
  [objs]
  (->> objs
       (map str)
       (str/join " ")))

(defn log
  "输出到插件日志"
  [& objs]
  (let [s (cat-msgs (-> (Thread/currentThread)
                        (.getName)
                        ((partial format "[%s]"))
                        (cons objs)))]
    (-> (extender/get)
        (.printOutput s))))

(defn alert
  [& objs]
  (let [s (cat-msgs objs)]
    (-> (extender/get)
        (.issueAlert s))))

(defmacro with-exception-default
  [value & body]
  `(try ~@body
        (catch Exception e#
          (do (log/error e#)
              ~value))))

(defn remove-all-proxy-listeners []
  (let [ext (extender/get)]
    (doseq [l (.getProxyListeners ext)]
      (.removeProxyListener ext l))))

(defn remove-all-context-menu []
  (let [ext (extender/get)]
    (doseq [f (.getContextMenuFactories ext)]
      (.removeContextMenuFactory ext f))))

(def-enum-fileds-map param-type IParameter PARAM_)
(def-enum-fileds-map request-content-type IRequestInfo CONTENT_TYPE_)
(def-enum-fileds-map intercept-action IInterceptedProxyMessage ACTION_)
(def-enum-fileds-map menu-invocation-context IContextMenuInvocation CONTEXT_)
(def-enum-fileds-map tool-type IBurpExtenderCallbacks TOOL_)

(defn parse-param [^IParameter param]
  (let [r {:name (.getName param)
          :type (-> (.getType param)
                    param-type-inv)
           :value (.getValue param)}]
    r))

(defn parse-cookie [^ICookie cookie]
  {:domain (.getDomain cookie)
   :expiration (.getExpiration cookie)
   :name (.getName cookie)
   :path (.getPath cookie)
   :value (.getValue cookie)})

(defn parse-headers
  [req-or-resp]
  (.getHeaders req-or-resp))

(defn parse-resp-cookies
  [^IResponseInfo resp]
  (->> (.getCookies resp)
       (mapv parse-cookie)))

(defn parse-req-url
  "解析请求url"
  [^IRequestInfo req]
  (try (.getUrl req)
       (catch Exception _ nil)))

(defn parse-req-params
  "解析所有请求参数"
  [^IRequestInfo req]
  (->> (.getParameters req)
       (mapv parse-param)))

(defn parse-body-offset
  "解析请求或响应的body开始位置"
  [req-or-resp]
  (.getBodyOffset req-or-resp))

(defn parse-req-content-type
  [^IRequestInfo req]
  (-> (.getContentType req)
      request-content-type-inv))

(defn parse-req-method
  "解析请求方法"
  [^IRequestInfo req]
  (.getMethod req))

(defn parse-request [^IRequestInfo req]
  {:method (parse-req-method req)
   :content-type (parse-req-content-type req)
   :body-offset (parse-body-offset req)
   :headers (parse-headers req)
   :params  (parse-req-params req)
   :url (parse-req-url req)})

(defn parse-http-service
  [^IHttpService service]
  {:host (.getHost service)
   :port (.getPort service)
   :protocol (.getProtocol service)})

(defn parse-status-code
  "解析返回的状态码"
  [^IResponseInfo resp]
  (.getStatusCode resp))

(defn parse-mime-type
  "`from-header` 是否从响应头中解析mime类型，
  如果为false，则从http body中推断mime类型, 默认为true"
  ([^IResponseInfo resp] (parse-mime-type resp true))
  ([^IResponseInfo resp from-header]
   (if from-header
     (.getStatedMimeType resp)
     (.getInferredMimeType resp))))

(defn parse-response [^IResponseInfo resp]
  {:headers (parse-headers resp)
   :state-mime-type (parse-mime-type resp)
   :status (parse-status-code resp)
   :body-offset (parse-body-offset resp)
   :cookies (parse-resp-cookies resp)})

(defn build-http-service
  ([host port use-https-or-protocol]
   (-> (get-helper)
       (.buildHttpService host port use-https-or-protocol))))

(defn ->http-service
  [service]
  (cond
    (instance? IHttpService service)
    service

    (map? service)
    (build-http-service (:host service)
                        (:port service)
                        (:protocol service))

    :else
    (throw (ex-info "unsupport http service type." {:service service}))))

(defn ->http-service-info
  [service]
  (cond
    (instance? IHttpService service)
    (parse-http-service service)

    (map? service)
    service

    :else
    (throw (ex-info "unsupport http service type." {:service service}))))

(defn get-full-host
  [service]
  (cond
    (instance? IHttpService service)
    (str service)

    (map? service)
    (str (:protocol service)
         "://"
         (:host service)
         (when-not (or
                    (and (= (:protocol service) "http")
                         (= (:port service) 80))
                    (and (= (:protocol service) "https")
                         (= (:port service) 443)))
           (str ":" (:port service))))

    :else
    (throw (ex-info "unsupport http service type." {:service service}))))

(defn analyze-request
  "分析请求"
  ([req]
   (-> (get-helper)
       (.analyzeRequest req)))
  ([http-service req]
   (-> (get-helper)
       (.analyzeRequest http-service req))))

(defn analyze-response
  "分析响应"
  [resp]
  (->> (cond-> resp
         (instance? IHttpRequestResponse resp) (.getResponse))
       (.analyzeResponse (get-helper))))

(defn base64-encode
  [s]
  (-> (get-helper)
      (.base64Encode s)))

(defn base64-decode
  [s]
  (-> (get-helper)
      (.base64Decode s)))

(defn build-parameter
  [name value type]
  (-> (get-helper)
      (.buildParameter name value (param-type type))))

(defn add-parameter
  [^bytes req-bs param]
  (-> (get-helper)
      (.addParameter req-bs param)))

(defn remove-parameter
  "删除请求的参数"
  [^bytes req-bs param]
  (-> (get-helper)
      (.removeParameter req-bs param)))

(defn update-parameter
  [^bytes req-bs param]
  (-> (get-helper)
      (.updateParameter req-bs param)))

(defn get-request-parameter
  [^bytes req-bs param-name]
  (-> (get-helper)
      (.getRequestParameter req-bs param-name)))

(defn build-http-request
  [url]
  (let [url (if (string? url)
              (as-url url)
              url)]
    (-> (get-helper)
        (.buildHttpRequest url))))

(defn build-http-message
  [headers ^bytes body]
  (-> (get-helper)
      (.buildHttpMessage headers body)))

(defn make-message-editor-controller
  [service req resp]
  (reify IMessageEditorController
    (getHttpService [this] service)
    (getRequest [this] req)
    (getResponse [this] resp)))

(defprotocol IRequestResponseEditorController
  (init [this editable])
  (get-request-editor [this])
  (get-response-editor [this])
  (set-message [this message])
  (get-message [this]))

(defn- get-message-bytes
  [msg]
  (-> (or msg (byte-array 0))
      utils/->bytes))

(defn make-request-response-controller
  []
  (let [data (atom nil)]
    (reify
      IRequestResponseEditorController
      (init [this editable]
        (let [req-editor (extender/create-message-editor this editable)
              resp-editor (extender/create-message-editor this editable)]
          (swap! data assoc
                 :request-editor req-editor
                 :response-editor resp-editor)))
      (get-message [this]
        (get @data :message))
      (set-message [this message]
        (if (= (get-message this) message)
          (log/info :request-response-controller :set-message "same message.")
          (let [req (-> (:request/raw message)
                        get-message-bytes)
                resp (-> (:response/raw message)
                         get-message-bytes)]
            (-> (get-request-editor this)
                (.setMessage req true))
            (-> (get-response-editor this)
                (.setMessage resp false))
            (swap! data assoc :message message))))
      (get-request-editor [this]
        (get @data :request-editor))
      (get-response-editor [this]
        (get @data :response-editor))

      IMessageEditorController
      (getHttpService [this]
        (when-let [msg (get-message this)]
          (build-http-service (:host msg) (:port msg) (:protocol msg))))
      (getRequest [this]
        (when-let [msg (get-message this)]
          (-> (:request/raw msg)
              get-message-bytes)))
      (getResponse [this]
        (when-let [msg (get-message this)]
          (-> (:response/raw msg)
              get-message-bytes))))))

(defn send-http-raw
  "发送http请求，返回 IHttpRequestResponse

  `service` IHttpService或者{:host host, :port port, :protocol \"http\"}
  `http-raw` 要发送的http原始消息
  "
  [http-raw service]
  (-> (->http-service service)
      (extender/make-http-req (utils/->bytes http-raw))))

(defn send-http-raw2
  "发送http请求，返回response bytes

  `service` IHttpService或者{:host host, :port port, :protocol \"http\"}
  `http-raw` 要发送的http原始消息
  "
  [http-raw service]
  (let [{:keys [host port protocol]} (->http-service-info service)]
    (extender/make-http-req host
                            port
                            (= "https" protocol)
                            (utils/->bytes http-raw))))

(defn ->msg-controller
  [^IHttpRequestResponse http-req-resp]
  (make-message-editor-controller (.getHttpService http-req-resp)
                                  (.getRequest http-req-resp)
                                  (.getResponse http-req-resp)))

(extender/defsetting :burp-clj/proxy {:enabled false
                                      :type "http"
                                      :host "127.0.0.1"
                                      :port 8080
                                      :non-proxy-hosts "127.0.0.1|localhost"
                                      })

(defn get-enabled-proxy
  []
  (let [proxy (get-proxy)]
    (when (:enabled proxy)
      (dissoc proxy :enabled))))

(defn add-dep-with-proxy
  [libs & args]
  (apply utils/add-dep libs
         :proxy (get-enabled-proxy)
         ;; :transfer-listener :stdout
         args))
