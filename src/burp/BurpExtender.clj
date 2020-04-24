(ns burp.BurpExtender
  "注意！文件名要和文件夹路径对应"
  (:require [nrepl.server :refer [start-server stop-server]]
            [clojure.spec.alpha :as s]
            [cemerick.pomegranate :refer [add-dependencies]])
  (:import [burp IBurpExtender IBurpExtenderCallbacks]
           [java.io PrintWriter])
  (:gen-class
   ;;:name BurpExtender
   ;; 这里不能省略package,import不起作用
   :implements [burp.IBurpExtender]
   :main false
   :prefix "-"))

(def default-repo (merge cemerick.pomegranate.aether/maven-central
                         {"clojars" "https://clojars.org/repo"}))
(defn add-dep
  [libs & {:keys [repos]
           :or {repos default-repo}}]
  (add-dependencies :coordinates libs :repositories repos))

(defn -registerExtenderCallbacks
  [this ^IBurpExtenderCallbacks callbacks]
  (.setExtensionName callbacks "clojure nrepl")
  (let [stdout (-> (.getStdout callbacks)
                   (PrintWriter. true))
        repl-port 22233]
    (.println stdout "clojure nrepl init....")
    (start-server :bind "0.0.0.0" :port repl-port)
    (.println stdout (str "nrepl started at" repl-port))))

