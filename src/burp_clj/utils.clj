(ns burp-clj.utils
  (:require [clojure.reflect :as reflect]
            [clojure.pprint :as pp]
            [camel-snake-kebab.core :as csk]
            [clojure.tools.gitlibs :as gitlib]
            [cemerick.pomegranate :as pg :refer [add-dependencies]]
            [clojure.string :as str])
  (:import [clojure.lang DynamicClassLoader RT])
  )

;;;;;;;;;;;;;;;; dep helper
(def default-repo (merge cemerick.pomegranate.aether/maven-central
                         {"clojars" "https://clojars.org/repo"}))

(defn ensure-dynamic-classloader
  "确保可以动态加载jar"
  []
  (let [thread (Thread/currentThread)
        context-class-loader (.getContextClassLoader thread)
        compiler-class-loader (.getClassLoader clojure.lang.Compiler)]
    (when-not (instance? DynamicClassLoader context-class-loader)
      (prn "set new dynamic classloader!!")
      (.setContextClassLoader
       thread (DynamicClassLoader. (or context-class-loader
                                       compiler-class-loader))))))

(defn base-classloader []
  (let [^DynamicClassLoader cl (RT/baseLoader)]
    (if-let [^DynamicClassLoader parent (.getParent cl)]
      parent
      (or cl (.. Thread currentThread getContextClassLoader)))))

(defn base-classloader-hierarchy []
  (pg/classloader-hierarchy (base-classloader)))

(defn find-top-classloader [classloaders]
  (last (filter pg/modifiable-classloader? classloaders)))

(defn get-dynamic-classloader
  []
  (try (prn "find top classloader.")
       (let [cl (-> (base-classloader-hierarchy)
                    find-top-classloader)]
         (if cl
           cl
           (ensure-dynamic-classloader)))
       (catch Exception e
         (ensure-dynamic-classloader))))

(defn add-dep
  [libs & {:keys [repos classloader]
           :or {repos default-repo}}]
  (let [classloader (or classloader
                        (ensure-dynamic-classloader))]
    (prn (-> (Thread/currentThread)
             (.getName)) "add deps.")
    (add-dependencies :coordinates libs
                      :repositories repos
                      :classloader classloader)))

(defn git-checkout
  "根据`rev` checkout git项目，
  成功则返回项目文件夹路径
  失败返回nil
  `key`用于checkout的keyword标识，必须带namespace"
  [url key rev]
  (gitlib/procure url key rev))

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

