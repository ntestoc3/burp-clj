(ns burp.core
  (:require [burp.extender :as extender]
            [burp.nrepl :as nrepl]
            [burp.cyber-chef :as cyber-chef])
  )

;;; 必须存在，extension加载时执行
(defn register
  "注册回调"
  [cbs]
  (.setExtensionName cbs "clojure all in one")
  (extender/set! cbs)
  (nrepl/start-nrepl)
  (.printOutput cbs "register ok!"))


(comment
  (extender/register-context-menu-factory! :cyber-chef (cyber-chef/cyber-chef-menu))

  (extender/remove-context-menu-factory! :cyber-chef )

  )
