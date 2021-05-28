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
           [java.awt.event HierarchyEvent HierarchyListener]
           [javax.swing.event AncestorListener]))

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
(defn burp-resource
  [path]
  (->> (.getClassLoader burp.ICookie)
       (io/resource path)))

(def burp-img (delay (-> (or (burp-resource "resources/Media/icon32.png")
                             (burp-resource "resources/Media/icon32pro.png"))
                         icon/icon
                         .getImage)))

(defn conform-dlg
  [{:keys [title content type]
    :or {type :plain}}]
  (let [dlg (-> (gui/dialog
                 :title title
                 :modal? true
                 :option-type :ok-cancel
                 :content content
                 :type type))]
    (-> (.getOwner dlg)
        (.setIconImage @burp-img))
    (-> dlg
        (gui/pack!)
        (gui/show!))))

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

(defn add-ancestor-listener
  "添加ancesotr事件监听

  `comp` 控件

  ｀opts` 选项:
  - `:add-cb` 	ANCESTOR_ADDED 回调函数，接受一个AncestorEvent参数, 控件显示时调用
  - `:move-cb` ANCESTOR_MOVED 回调函数,接受一个AncestorEvent参数, 控件显示并且移动时调用
  - `:remove-cb` ANCESTOR_REMOVED 回调函数,接受一个AncestorEvent参数, 控件隐藏时调用
  - `:once` 是否只调用一次，默认为false
  "
  [comp {:keys [add-cb
                move-cb
                remove-cb
                once]}]
  (.addAncestorListener comp
                        (reify AncestorListener
                          (ancestorAdded [this e]
                            (when add-cb
                              (add-cb e))
                            (when once
                              (.removeAncestorListener comp this)))
                          (ancestorMoved [this e]
                            (when move-cb
                              (move-cb e))
                            (when once
                              (.removeAncestorListener comp this)))
                          (ancestorRemoved [this e]
                            (when remove-cb
                              (remove-cb e))
                            (when once
                              (.removeAncestorListener comp this))))))

(defn add-showing-listener
  "添加控件显示事件

  `comp` 要添加事件的控件

  `callback` 无参数的回调函数

  `opts` 可选参数:
  - `:showing` 控件显示时回调，默认为true,如果为false,则在控件不可见时回调
  - `:once` 只调用一次,默认为true,如果为false,则控件每次显示或隐藏时都会调用
  "
  ([comp callback] (add-showing-listener comp callback nil))
  ([comp callback {:keys [showing once]
                   :or {showing true
                        once true}}]
   (.addHierarchyListener
    comp
    (reify java.awt.event.HierarchyListener
      (hierarchyChanged [this e]
        (when (and (not= 0 (bit-and
                            ^Integer (.getChangeFlags e)
                            ^Integer HierarchyEvent/SHOWING_CHANGED))
                   (cond-> (.isShowing comp)
                     (not showing) not))
          (callback)
          (when once
            (.removeHierarchyListener comp this))))))))

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

(defmacro decorator
  [clazz proto & fs]
  (let [proto-name (gensym "proto")
        methods (->> (clojure.reflect/reflect (resolve clazz))
                  :members
                  (filter #(instance? clojure.reflect.Method %))
                  (map (fn [{:keys [name parameter-types]}]
                         [name (count parameter-types)]))
                  set)
        to-delegate (clojure.set/difference
                      methods
                      (->> fs
                        (map (fn [[name params]]
                               [name (count params)]))
                        set))
        method-bodies
        (concat
          fs ;; these are our own definitions
          (for [[name n-params] to-delegate]
            (let [params (->> (range n-params)
                           (map #(gensym (str "x" %))))]
              `(~name [~@params]
                 (. ~proto-name (~name ~@params))) ;; this is where we delegate to the prototype
              )))]
    `(let [~proto-name ~proto]
       (proxy
         [~clazz] []
         ~@(->> method-bodies (group-by first) (sort-by first)
             (map (fn [[name bodies]]
                    `(~name ~@(for [[name & rest] bodies]
                                rest)))))))))

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

(defn ->bytes
  "转换为bytes

  `:encoding` 如果data是字符串，指定字符串编码，默认为ISO-8859-1(与字符串互转，符号位不丢失)
  "
  ([data] (->bytes data "ISO-8859-1"))
  ([data encoding]
   (cond
     (bytes? data) data
     (string? data) (.getBytes data encoding)
     (nil? data) (byte-array 0)
     :else (throw (ex-info (format "unsupport ->bytes format: %s." (type data))
                           {:data data})))))

(defn ->string
  "转换为string

  `:encoding` 转换为目标字符串的编码，默认为ISO-8859-1(与bytes互转，符号位不丢失),如果data是字符串，则不做转换"
  ([data] (->string data "ISO-8859-1"))
  ([data encoding]
   (cond
     (string? data) data
     (bytes? data) (String. data encoding)
     :default (str data))))

(defn concat-byte-arrays
  [& byte-arrays]
  (when (not-empty byte-arrays)
    (let [total-size (reduce + (map count byte-arrays))
          result     (byte-array total-size)
          bb         (java.nio.ByteBuffer/wrap result)]
      (doseq [ba byte-arrays]
        (.put bb ba))
      result)))

;;;;; time helper
(defmacro time-execution
  [& body]
  `(let [s# (new java.io.StringWriter)]
     (binding [*out* s#]
       (hash-map :return (time ~@body)
                 :time   (-> (.replaceAll (str s#) "[^0-9\\.]" "")
                             (Double/parseDouble))))))
