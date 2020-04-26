(ns burp-clj.validate
  )

(defn valid-port?
  [^Integer port]
  (< 0 port 65536))

