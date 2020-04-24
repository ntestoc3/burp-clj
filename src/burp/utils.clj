(ns burp.utils
  (:require [clojure.reflect :as reflect]
            [clojure.pprint :as pp]
            [camel-snake-kebab.core :as csk]
            [cemerick.pomegranate :refer [add-dependencies]]
            [clojure.string :as str]
            [burp.extender :as extender]
            )
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
            IContextMenuFactory]
           ))

;;;;;;;;;;;;;;;; dep helper
(def default-repo (merge cemerick.pomegranate.aether/maven-central
                         {"clojars" "https://clojars.org/repo"}))
(defn add-dep
  [libs & {:keys [repos]
           :or {repos default-repo}}]
  (add-dependencies :coordinates libs :repositories repos))

;;;;;;;;;;;;; class helper
(defn get-classinfo
  [class]
  (->> (reflect/reflect class)
       :members
       (sort-by :name)))

(defn print-classinfo
  [class]
  (->> (get-classinfo class)
       (pp/print-table [:name :flags :parameter-types :return-type])))

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

;;;;;;;; extender utils

(defn get-helper []
  (-> (extender/get)
      .getHelpers))

(defn log [& objs]
  (let [s (->> objs
               (map str)
               (str/join " "))]
    (-> (extender/get)
        (.printOutput s))))

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
  "分析响应"
  [resp]
  (let [resp-info (-> (get-helper)
                      (.analyzeResponse resp))]
    {:headers (.getHeaders resp-info)
     :state-mime-type (.getStatedMimeType resp-info)
     :status (.getStatusCode resp-info)
     :body-offset (.getBodyOffset resp-info)
     :cookies (->> (.getCookies resp-info)
                   (map parse-cookie))}))

