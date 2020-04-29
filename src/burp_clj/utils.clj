(ns burp-clj.utils
  (:require [clojure.reflect :as reflect]
            [clojure.pprint :as pp]
            [camel-snake-kebab.core :as csk]
            [clojure.tools.gitlibs :as gitlib]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]
            [cemerick.pomegranate :as pg :refer [add-dependencies]]
            [seesaw.core :as gui]
            [clojure.string :as str]
            [me.raynes.fs :as fs])
  (:import [clojure.lang DynamicClassLoader RT])
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
  [libs & {:keys [repos classloader]
           :or {repos default-repo}}]
  (prn (-> (Thread/currentThread)
           (.getName))
       "class paths:")
  (doseq  [cp (-> (pg/classloader-hierarchy)
                  pg/get-classpath)]
    (prn cp))
  (prn "base class loader paths:")
  (doseq  [cp (-> (pg/classloader-hierarchy base-class-loader)
                  pg/get-classpath)]
    (prn cp))
  (let [classloader (ensure-dynamic-classloader)]
    (add-dependencies :coordinates libs
                      :repositories repos
                      :classloader classloader)))
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

;;; ui
(defn show-ui
  ([widget]
   (gui/native!)
   (let [f (gui/frame :title "test ui"
                      :on-close :dispose
                      :content widget)]
     (-> f gui/pack! gui/show!)
     f)))

(defn table-model-listener
  [handler]
  (reify javax.swing.event.TableModelListener
    (tableChanged [this e] (handler e))))

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
