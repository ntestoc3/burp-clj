(ns burp-clj.http-message
  (:require [burp-clj.helper :as helper]
            [camel-snake-kebab.core :as csk]
            [burp-clj.utils :as utils]
            [clojure.string :as str])
  (:import [java.net URLEncoder URLDecoder]))

;;; params helper
(defn encode-params
  ([request-params] (encode-params request-params nil))
  ([request-params {:keys [coding key-fn]
                    :or {coding "UTF-8"
                         key-fn name}}]
   (let [encode #(URLEncoder/encode (str %) coding)
         coded (for [[n v] request-params] (str (encode (key-fn n))
                                                "="
                                                (encode v)))]
     (apply str (interpose "&" coded)))))

(defn decode-params
  ([params] (decode-params params nil))
  ([params {:keys [coding key-fn]
            :or {coding "UTF-8"
                 key-fn csk/->kebab-case-keyword}}]
   (let [decode #(URLDecoder/decode (str %) coding)]
     (->> (str/split params #"&")
          (map #(let [[k v] (-> %1
                                (str/split #"=" 2))]
                  [(key-fn (decode k))
                   (decode v)]))
          (into {})))))

;;;;; header helpers
;;;;;;;;;;; http helper
(defn- gen-format-fn
  [{:keys [ignore-case
           ignore-space]
    :or {ignore-case true
         ignore-space true}}]
  (->> (cond-> []
         ignore-case (conj str/lower-case)
         ignore-space (conj str/trim)
         :always (conj name))
       (apply comp)))

(defn parse-headers
  "解析http header, 忽略status line
  `hls`为包含HTTP header line的seq
  `k` 要查找的key

  可选选项
  :key-fn key转换函数，默认转换为clojure keyword格式
  :val-fn value转换函数，默认为`clojure.string/trim`
  "
  ([hls] (parse-headers hls nil))
  ([hls {:keys [key-fn val-fn]
         :or {key-fn csk/->kebab-case-keyword
              val-fn str/trim}}]
   (->> hls
        ;; TODO 这里为了兼容性,header kv的分隔没有加空格
        (map #(str/split %1 #":" 2))
        (filter #(= 2 (count %)))
        (map (fn [[k v]] [(key-fn k)
                          (val-fn v)])))))

(defn get-headers
  "从hdr中查找k的所有值,结果为seq类型

  `hdr` http header结构
  `k` 要查找的key

  可选选项:
  :ignore-case 比较header key忽略大小写,默认为true
  :ignore-space 比较header key忽略首尾空格,默认为true
  "
  ([hdr k] (get-headers hdr k nil))
  ([hdr k opts]
   (let [format-fn (gen-format-fn opts)
         find-k (format-fn k)]
     (->> hdr
          (map (fn [[k v]]
                 (when (= find-k (format-fn k))
                   v)))
          (filter identity)))))

(defn insert-headers
  "向http头结构中插入http头,hdr与hdr2结构相同

  `pos-k`  如果指定`pos-k`，则在`pos-k`之前或之后插入hdr2 http头,否则在最后插入hdr2

  可选选项:
  :ignore-case 比较key忽略大小写,默认为true
  :ignore-space 比较key忽略首尾空格,默认为true
  :insert-before 如果为true,则在`pos-k`项之前插入`hdr2`,默认为false
  "
  ([hdr hdr2]
   (concat hdr hdr2))
  ([hdr hdr2 pos-k]
   (insert-headers hdr hdr2 pos-k nil))
  ([hdr hdr2 pos-k {:keys [insert-before] :as opts}]
   (let [format-fn (gen-format-fn opts)
         find-k (format-fn pos-k)
         [left right] (split-with
                       (fn [[k _]]
                         (not (= find-k (format-fn k))))
                       hdr)]
     (apply concat left (if insert-before
                          [hdr2 right]
                          [(when (seq right)
                             (take 1 right))
                           hdr2
                           (rest right)])))))

(defn find-index-kv
  ([hdr k] (find-index-kv hdr k nil))
  ([hdr k opts]
   (let [format-fn (gen-format-fn opts)
         find-k (format-fn k)]
     (->> hdr
          (keep-indexed (fn [idx [k v]]
                          (when (= find-k (format-fn k))
                            [idx k v])))
          first))))

(defn update-header
  "修改http headere的值
  `k` 要修改的header key,如果找不到,则在header最后添加k v
  `f` 更新函数(f v),v为k对应的值,如果找不到则为nil

  可选选项:
  :ignore-case 比较key忽略大小写,默认为true
  :ignore-space 比较key忽略首尾空格,默认为true
  :keep-old-key 是否使用原先的key,默认为true,
                如果为flase，则使用`k`代替原先的key
                如果找不到key，总是使用给定的`k`
  "
  ([hdr k f] (update-header hdr k f nil))
  ([hdr k f {:keys [keep-old-key]
             :or {keep-old-key true}
             :as opts}]
   (let [[idx old-k v] (or (find-index-kv hdr k opts)
                           [(count hdr) k nil])]
     (utils/assoc-at hdr idx [(if keep-old-key
                                old-k
                                k)
                              (f v)]))))

(defn assoc-header
  "修改http headere的值
  `k` 要修改的header key,如果找不到,则在header最后添加k v

  可选选项:
  :ignore-case 比较key忽略大小写,默认为true
  :ignore-space 比较key忽略首尾空格,默认为true
  :keep-old-key 是否使用原先的key,默认为true,
                如果为flase，则使用`k`代替原先的key
                如果找不到key，总是使用给定的`k`
  "
  ([hdr k v] (assoc-header hdr k v nil))
  ([hdr k v {:keys [keep-old-key]
             :or {keep-old-key true}
             :as opts}]
   (update-header hdr k (constantly v) opts)))

;;;;; request response
(defn- parse-content-type-info
  [headers opts]
  (let [[content-type charset & _] (some-> (get-headers headers :content-type opts)
                                           first
                                           ;; 有时会带encoding
                                           ;; 比如:application/x-www-form-urlencoded;charset=UTF-8
                                           ;; application/json;charset=UTF-8
                                           (str/split #";\s*"))]
    {:content-type content-type
     :charset (when (and charset
                         (str/starts-with? charset "charset="))
                (-> (subs charset 8)
                    str/trimr))}))

(defn parse-request
  "解析http请求

  `opts`参数:
  - :key-fn http header key转换函数，默认转换为clojure keyword格式
  - :val-fn http header value转换函数，默认为`clojure.string/trim`"
  ([req] (parse-request req nil))
  ([req opts]
   (when req
     (let [ana-req (helper/analyze-request req)
           body-offset (helper/parse-body-offset ana-req)
           [start-line & headers] (-> (java.util.Arrays/copyOfRange req 0 body-offset)
                                      (utils/->string)
                                      (str/split #"\r?\n"))
           [method uri http-ver] (-> (str/trim start-line)
                                     (str/split #"\s+"))
           headers (parse-headers headers opts)
           {:keys [content-type charset]} (parse-content-type-info headers opts)
           req-len (count req)]
       {:method (csk/->kebab-case-keyword method)
        :content-type (or content-type
                          "application/x-www-form-urlencoded")
        :charset charset
        :url uri
        :version (-> (str/split http-ver #"/")
                     last)
        :headers headers
        :body (when (< body-offset req-len)
                (java.util.Arrays/copyOfRange req body-offset req-len))}))))

(defn parse-response
  "解析http响应

   `opts`参数:

  解析header相关
  :key-fn key转换函数，默认转换为clojure keyword格式
  :val-fn value转换函数，默认为`clojure.string/trim`
  "
  ([resp] (parse-response resp nil))
  ([resp opts]
   (when resp
     (let [ana-resp (helper/analyze-response resp)
           body-offset (helper/parse-body-offset ana-resp)
           [start-line & headers] (-> (java.util.Arrays/copyOfRange resp 0 body-offset)
                                      (utils/->string)
                                      (str/split #"\r?\n"))
           [http-ver status-code] (-> (str/trim start-line)
                                      (str/split #"\s+"))
           headers (parse-headers headers opts)
           {:keys [content-type charset]} (parse-content-type-info headers opts)
           resp-len (count resp)]
       {:status (utils/try-parse-int status-code)
        :version (-> (str/split http-ver #"/")
                     last)
        :content-type (or content-type
                          "text/html")
        :charset charset
        :mime-type (let [state-mime (helper/parse-mime-type ana-resp true)]
                     (if (empty? state-mime)
                       (helper/parse-mime-type ana-resp false)
                       state-mime))
        :headers headers
        :body (when (< body-offset resp-len)
                (java.util.Arrays/copyOfRange resp body-offset resp-len))}))))

(defn- space-leader
  "添加前导空格"
  [s]
  (str " " s))

(defn build-headers-raw
  "构造http headers

  可选参数:
  :key-fn http header key转换函数，默认转换为HttpHeaderCase格式
  :val-fn http header value转换函数，默认为`space-leader` "
  ([headers] (build-headers-raw headers nil))
  ([headers {:keys [key-fn val-fn]
             :or {key-fn csk/->HTTP-Header-Case-String
                  val-fn space-leader}}]
   (->> headers
        (map (fn [[k v]]
               (str (key-fn k)
                    ":" ;; 这里分隔符后面的空格作为value的一部分进行处理
                    (val-fn v))))
        (str/join "\r\n"))))

(defn- can-have-content-length?
  [headers body-len]
  (if (first (get-headers headers :content-length))
    true
    ;; 如果没有content-length头，则要body大于0
    (and (pos? body-len)
         ;; 并且transfer-encoding不能为chunked
         (->> (get-headers headers :transfer-encoding)
              first
              (not= "chunked")))))

(defn build-request-raw
  "构造http原始请求字符串,返回bytes

  `data` 参数
  :body 必须为byte-array

  `opts`参数
  - :fix-content-length 修正Content-Length的值，默认为true
  - :key-fn http header key转换函数，默认转换为HttpHeaderCase格式
  - :val-fn http header value转换函数，默认为identity "
  ([data] (build-request-raw data nil))
  ([{:keys [method
            url
            version
            body
            headers]
     :or {method :get
          url "/"
          version "1.1"}}
    {:keys [fix-content-length]
     :or {fix-content-length true}
     :as opts}]
   (let [headers (cond-> headers
                   (and fix-content-length
                        (can-have-content-length? headers (count body)))
                   (assoc-header "Content-Length" (count body) {:keep-old-key false}))]
     (utils/concat-byte-arrays
      (utils/->bytes
       (str (-> (name method)
                str/upper-case) " " url " HTTP/" version "\r\n"
            (build-headers-raw headers opts)
            "\r\n\r\n"))
      (utils/->bytes body)))))


(defn flatten-format-req-resp
  "格式化req或resp
  `req-or-resp` 请求或响应的结果
  `format-type`只能是:request或:response, 默认为:request"
  ([req-or-resp] (flatten-format-req-resp req-or-resp :request))
  ([req-or-resp format-type]
   (-> (if (= :request format-type)
         (parse-request req-or-resp)
         (parse-response req-or-resp))
       (update :headers #(into {} %1))
       (utils/map->nsmap format-type true))))

(defn parse-http-req-resp
  "解析http req resp消息，
  `req-resp` IHttpRequestResponse"
  [req-resp]
  (let [req (.getRequest req-resp)
        resp (.getResponse req-resp)
        service (-> (.getHttpService req-resp)
                    helper/parse-http-service)]
    (merge
     {:comment (.getComment req-resp)
      :request/raw req
      :response/raw resp
      :full-host (helper/get-full-host service)}
     service
     (flatten-format-req-resp req :request)
     (flatten-format-req-resp resp :response))))
