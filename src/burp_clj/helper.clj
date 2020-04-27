(ns burp-clj.helper
  (:require [clojure.string :as str]
            [clojure.java.io :refer [as-url]]
            [burp-clj.extender :as extender]
            [burp-clj.utils :refer [def-enum-fileds-map]])
  (:refer-clojure :exclude [alert])
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
            IContextMenuFactory]))

(defn get-helper []
  (-> (extender/get)
      .getHelpers))

(defn cat-msgs
  [objs]
  (->> objs
       (map pr-str)
       (str/join " ")))

(defn log
  "输出到插件日志"
  [& objs]
  (let [s (cat-msgs objs)]
    (-> (extender/get)
        (.printOutput s))))

(defn alert
  [& objs]
  (let [s (cat-msgs objs)]
    (-> (extender/get)
        (.issueAlert s))))

(defmacro with-exception-default
  [value & body]
  `(try ~body
        (catch Exception e#
          (do (alert "exception:" e#)
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

(defn parse-request [^IRequestInfo req]
  {:method (.getMethod req)
   :content-type (-> (.getContentType req)
                     request-content-type-inv)
   :body-offset (.getBodyOffset req)
   :headers (.getHeaders req)
   :params  (->> (.getParameters req)
                 (mapv parse-param))
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
  "分析响应"
  [resp]
  (let [resp-info (-> (get-helper)
                      (.analyzeResponse resp))]
    {:headers (.getHeaders resp-info)
     :state-mime-type (.getStatedMimeType resp-info)
     :status (.getStatusCode resp-info)
     :body-offset (.getBodyOffset resp-info)
     :cookies (->> (.getCookies resp-info)
                   (mapv parse-cookie))}))

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
  [req-bs param]
  (-> (get-helper)
      (.addParameter req-bs param)))

(defn remove-parameter
  [req-bs param]
  (-> (get-helper)
      (.removeParameter req-bs param)))

(defn update-parameter
  [req-bs param]
  (-> (get-helper)
      (.updateParameter req-bs param)))

(defn get-request-parameter
  [req-bs param-name]
  (-> (get-helper)
      (.getRequestParameter req-bs param-name)))

(defn build-http-request
  [url]
  (let [url (if (string? url)
              (as-url url)
              url)]
    (-> (get-helper)
        (.buildHttpRequest url))))

(defn build-http-service
  ([host port use-https-or-protocol]
   (-> (get-helper)
       (.buildHttpService host port use-https-or-protocol))))

(defn bytes->str
  [bs]
  (-> (get-helper)
      (.bytesToString bs)))

(defn- find-headers-key
  "find headers key name"
  [headers k]
  (let [target-k (-> k name str/lower-case)]
    (->> headers
         (filter (fn [[k v]]
                   (= (-> k str/lower-case str/trim)
                      target-k)))
         ffirst)))

(defn get-headers-v
  "get headers value by header-k"
  [headers header-k]
  (->> (find-headers-key headers header-k)
       (get headers)))

(defn parse-raw-http
  [raw]
  (let [[headers body] (str/split raw #"\r?\n\r?\n" 2)
        [start-line & headers] (str/split headers #"\r?\n")
        [method uri http-ver] (str/split start-line #"\s")
        headers (->> headers
                     (map #(str/split %1 #":\s+" 2))
                     (filter #(= 2 (count %)))
                     (into {}))]
    {:request-method (-> method
                         str/lower-case
                         keyword)
     :server-name (get-headers-v headers :host)
     :http-ver http-ver
     :uri uri
     :headers headers
     :body body}))
