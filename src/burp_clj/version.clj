(ns burp-clj.version
  (:require [burp-clj.extender :as extender]
            [clojure.java.io :as io])
  (:import java.util.jar.JarInputStream)
  (:gen-class))

(defn get-version []
  (-> (eval 'burp_clj.version)
      .getPackage
      .getImplementationVersion))

(defn get-version2 []
  (-> (extender/get-extension-path)
      (io/input-stream)
      (JarInputStream.)
      (.getManifest)
      (.getMainAttributes)
      (.getValue "Implementation-Version")))
