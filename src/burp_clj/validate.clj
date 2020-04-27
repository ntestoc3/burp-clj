(ns burp-clj.validate
  (:require [me.raynes.fs :as fs]
            [burp-clj.utils :as utils]))

(defn valid-script-soruce?
  [url]
  )

(defn valid-port?
  [^Integer port]
  (< 0 port 65536))

