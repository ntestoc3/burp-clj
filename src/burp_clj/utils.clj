(ns burp-clj.utils
  (:require [clojure.reflect :as reflect]
            [clojure.pprint :as pp]
            [camel-snake-kebab.core :as csk]
            [clojure.tools.gitlibs :as gitlib]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]
            [cemerick.pomegranate :as pg :refer [add-dependencies]]
            [seesaw.core :as gui]
            [seesaw.icon :as icon]
            [clojure.string :as str]
            [me.raynes.fs :as fs]
            [clojure.java.io :as io])
  (:import [clojure.lang DynamicClassLoader RT]
           burp.IHttpRequestResponse
           [java.net URLEncoder URLDecoder])
  )

;;;;;;;;;;;;;;;; dep helper
(def default-repo (merge cemerick.pomegranate.aether/maven-central
                         {"clojars" "https://clojars.org/repo"}))

(def base-class-loader (DynamicClassLoader. (.getClassLoader clojure.lang.Compiler)))
(defn ensure-dynamic-classloader
  "确保可以动态加载jar"
  []
  (let [thread (Thread/currentThread)
        context-class-loader (.getContextClassLoader thread)]
    (when-not (instance? DynamicClassLoader context-class-loader)
      (prn "set new dynamic classloader for thread:" (.getName thread))
      (.setContextClassLoader thread base-class-loader))))

(defn add-cp
  [jar-or-dir]
  (pg/add-classpath jar-or-dir base-class-loader))

(defn prn-cp
  []
  (-> (pg/get-classpath [base-class-loader])
      clojure.pprint/pprint))

(defn add-dep
  [libs & {:keys [repositories proxy]
           :or {repositories default-repo}
           :as args}]
  (log/info :add-dep "class paths:"
            (-> (pg/classloader-hierarchy)
                pg/get-classpath
                vec)
            "base class loader paths:"
            (-> (pg/classloader-hierarchy base-class-loader)
                pg/get-classpath
                vec)
            (when proxy
              (str "use proxy: " proxy)))
  (let [classloader (ensure-dynamic-classloader)]
    (apply add-dependencies
           :coordinates libs
           :repositories repositories
           :classloader classloader
           (apply concat (dissoc args :repositories)))))

(defn gen-gitkey
  [url]
  (->> (str/split url #"/")
       (take-last 2)
       (apply keyword )))

(defn git-checkout
  "根据`rev` checkout git项目，
  成功则返回项目文件夹路径
  失败返回nil
  `key`用于checkout的keyword标识，必须带namespace"
  ([url] (git-checkout url "master"))
  ([url rev]  (git-checkout url
                            (gen-gitkey url)
                            rev))
  ([url key rev]
   (gitlib/procure url key rev)))

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

;;;;;; log helper
(defn log-time-format! []
  (log/merge-config!
   {:timestamp-opts
    {:pattern "yyyy/MM/dd HH:mm:ss"
     :locale (java.util.Locale/getDefault)
     :timezone (java.util.TimeZone/getDefault)}}))

(defn make-log-appender
  "日志添加器
  `log-fn`"
  [log-fn]
  {:enabled? true
   :async? true
   :min-level nil
   :rate-limit nil
   :output-fn :inherit
   :fn log-fn})

(defn log-add-appender!
  "添加日志记录项"
  [appender]
  (log/merge-config!
   {:appenders appender}))

(defn log-to-fn!
  "配置log输出到函数回调
  `fn-key`为log appender的键"
  [fn-key log-fn]
  (log-add-appender! {fn-key (make-log-appender log-fn)}))

;;; load-file 代替，修正路径
(defn load-script
  "相对路径使用*cwd*加载clj文件
  绝对路径直接加载"
  [path]
  (if (fs/absolute? path)
    (load-file path)
    (load-file (str (fs/file fs/*cwd* path)))))

;;;;;;;;;;; gui helper
(def burp-img (delay (-> "resources/Media/icon32.png"
                         (io/resource (.getClassLoader burp.ICookie))
                         icon/icon
                         .getImage)))

(defn show-ui
  ([widget] (show-ui widget nil))
  ([widget opts]
   ;; (gui/native!)
   (let [f (apply gui/frame (-> {:title "test ui"
                                 :on-close :dispose
                                 :icon @burp-img
                                 :content widget}
                                (merge opts)
                                (->> (apply concat))))]
     (-> f gui/pack! gui/show!)
     f)))

(defn table-model-listener
  [handler]
  (reify javax.swing.event.TableModelListener
    (tableChanged [this e] (handler e))))

(defn fix-font!
  "修正font, burp的UI Font类型为awt.Font, 修正为FontUIResource
  解决swingx table初始化失败的问题"
  []
  (let [old-font (-> (javax.swing.UIManager/getFont "Label.font"))]
    (when-not (instance? javax.swing.plaf.FontUIResource old-font)
      (->> (javax.swing.plaf.FontUIResource. old-font)
           (javax.swing.UIManager/put "Label.font")))))


;;;; object helper
(defmacro override-delegate
  "重写`delegate`对象的某些方法"
  [type delegate & body]
  (let [d (gensym)
        overrides (group-by first body)
        methods (for [m (.getMethods (resolve type))
                      :let [f (-> (.getName m)
                                  symbol
                                  (with-meta {:tag (-> m .getReturnType .getName)}))]
                      :when (not (overrides f))
                      :let [args (for [t (.getParameterTypes m)]
                                   (with-meta (gensym) {:tag (.getName t)}))]]
                  (list f (vec (conj args 'this))
                        `(. ~d ~f ~@(map #(with-meta % nil) args))))]
    `(let [~d ~delegate]
       (reify ~type ~@body ~@methods))))

(defmacro dyn-call
  [ns-sym]
  (let [ns (-> (namespace ns-sym)
               symbol)
        sym (-> (name ns-sym)
                symbol)]
    `(do
       (require '~ns)
       (ns-resolve '~ns '~sym))))

(defn invoke-private-method [obj fn-name-string & args]
  (let [m (first (filter (fn [x] (.. x getName (equals fn-name-string)))
                         (.. obj getClass getDeclaredMethods)))]
    (. m (setAccessible true))
    (. m (invoke obj (into-array Object args)))))


(defn private-field [obj fn-name-string]
  (let [m (.. obj getClass (getDeclaredField fn-name-string))]
    (. m (setAccessible true))
    (. m (get obj))))

(defn class-private-field [class-field]
  (let [cls (-> (namespace class-field)
                symbol
                resolve)
        field (name class-field)
        m (.getDeclaredField cls field)]
    (. m (setAccessible true))
    (.get m nil)))

(defn load-exp
  "如果是错误的表达式则抛出异常,否则返回表达式函数"
  [exp-s]
  (add-dep []) ;; 必须加载依赖,否则在awt线程中会执行失败！
  (let [exp (-> (format "(fn [msg] %s)" exp-s)
                (load-string))]
    (exp {})
    exp))

;;;;;;;;;;; map helper

(defn ns-keyword
  "为keyword k添加命名空间n限定,
  如果overwrite为true，则覆盖已有的命名空间,默认为false"
  ([k n] (ns-keyword k n false))
  ([k n overwrite]
   (if (or overwrite
           (not (qualified-keyword? k)))
     (keyword (name n) (name k))
     k)))

(defn map->nsmap
  "转换map的所有key到命名空间n限定的key
  如果overwrite为true，则覆盖已有的命名空间,默认为false
  `deep` 为true则转换嵌套map为命名空间，嵌套的key为ns路径,默认为false"
  ([m n] (map->nsmap m n false))
  ([m n deep] (map->nsmap m n deep false))
  ([m n deep overwrite]
   (reduce-kv (fn [acc k v]
                (if (and deep (map? v))
                  (let [new-ns (str (name n) "." (name k))
                        sub-map (map->nsmap v new-ns deep overwrite)]
                    (merge acc sub-map))
                  (let [new-kw (ns-keyword k n overwrite)]
                    (assoc acc new-kw v))))
              {} m)))

(defn assoc-at [data i item]
  (if (associative? data)
    (assoc data i item)
    (if-not (neg? i)
      (letfn [(assoc-lazy [i data]
                (cond (zero? i) (cons item (rest data))
                      (empty? data) data
                      :else (lazy-seq (cons (first data)
                                            (assoc-lazy (dec i) (rest data))))))]
        (assoc-lazy i data))
      data)))

;;;;;;;;;;; converter helper
(defn try-parse-int
  ([s] (try-parse-int s 0))
  ([s default-value]
   (try (Integer/parseInt s)
        (catch Exception e default-value))))

(defn try-parse-long
  ([s] (try-parse-long s 0))
  ([s default-value]
   (try (Long/parseLong s)
        (catch Exception e default-value))))

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
     (assoc-at hdr idx [(if keep-old-key
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

(defn ->bytes
  [data]
  (cond
    (bytes? data) data
    (string? data) (.getBytes data)
    :else (throw (ex-info (format "unsupport ->bytes format: %s." (type data))
                          {:data data}))))

(defn ->string
  [data]
  (cond
    (string? data) data
    (bytes? data) (String. data)
    :else (throw (ex-info (format "unsupport ->string format: %s." (type data))
                          {:data data}))))

(defn- ->http-raw
  [msg]
  (cond
    (string? msg) msg
    (bytes? msg) (String. msg)
    :else (throw (ex-info "unsupport http message type." {:msg msg}))))

(defn parse-request
  "解析http请求

  `opts`参数:

  解析header相关
  :key-fn http header key转换函数，默认转换为clojure keyword格式
  :val-fn value转换函数，默认为`clojure.string/trim`"
  ([req] (parse-request req nil))
  ([req opts]
   (when req
     (let [[headers body] (-> (->http-raw req)
                              (str/split #"\r?\n\r?\n" 2))
           [start-line & headers] (str/split headers #"\r?\n")
           [method uri http-ver] (-> (str/trim start-line)
                                     (str/split #"\s+"))
           headers (parse-headers headers opts)]
       {:method (csk/->kebab-case-keyword method)
        :url uri
        :version (-> (str/split http-ver #"/")
                     last)
        :headers headers
        :body (when (seq body)
                body)}))))

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
     (let [[headers body] (-> (->http-raw resp)
                              (str/split #"\r?\n\r?\n" 2))
           [start-line & headers] (str/split headers #"\r?\n")
           [http-ver status-code] (-> (str/trim start-line)
                                      (str/split #"\s+"))
           headers (parse-headers headers opts)]
       {:status (try-parse-int status-code)
        :version (-> (str/split http-ver #"/")
                     last)
        :headers headers
        :body body}))))

(defn space-leader
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

(defn can-have-content-length?
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
  "构造http原始请求字符串


  `opts`参数
  :fix-content-length 修正Content-Length的值，默认为true
  :key-fn http header key转换函数，默认转换为HttpHeaderCase格式
  :val-fn http header value转换函数，默认为identity "
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
     (str (-> (name method)
              str/upper-case) " " url " HTTP/" version "\r\n"
          (build-headers-raw headers opts)
          "\r\n\r\n"
          body))))

;;;;; time helper
(defmacro time-execution
  [& body]
  `(let [s# (new java.io.StringWriter)]
     (binding [*out* s#]
       (hash-map :return (time ~@body)
                 :time   (-> (.replaceAll (str s#) "[^0-9\\.]" "")
                             (Double/parseDouble))))))
;;; url helper
(defn encode-params [request-params]
  (let [encode #(URLEncoder/encode (str %) "UTF-8")
        coded (for [[n v] request-params] (str (encode (name n))
                                               "="
                                               (encode v)))]
    (apply str (interpose "&" coded))))

(defn decode-params [params]
  (let [decode #(URLDecoder/decode (str %) "UTF-8")]
    (->> (str/split params #"&")
         (map #(let [[k v] (-> %1
                               (str/split #"=" 2))]
                 [(csk/->kebab-case-keyword (decode k))
                  (decode v)]))
         (into {}))))
