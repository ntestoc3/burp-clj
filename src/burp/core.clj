(ns burp.core
  (:require [burp.extender :as extender]
            [burp.nrepl :as nrepl]
            [burp.cyber-chef :as cyber-chef]
            [burp.shiro-check :as shiro-check])
  )

;;; 必须存在，extension加载时执行
(defn register
  "注册回调"
  [cbs]
  (.setExtensionName cbs "clojure plugins")
  (extender/set! cbs)
  (nrepl/start-nrepl)
  (.printOutput cbs "register cyber-chef!")
  (extender/register-context-menu-factory! :cyber-chef (cyber-chef/cyber-chef-menu))

  (.printOutput cbs "register shiro-check!")
  (extender/register-proxy-listener! :shiro-check (shiro-check/shiro-check-proxy))

  (.printOutput cbs "register ok!"))


(comment
  (extender/register-context-menu-factory! :cyber-chef (cyber-chef/cyber-chef-menu))

  (extender/remove-context-menu-factory! :cyber-chef )

  (extender/register-proxy-listener! :shiro-check (shiro-check/shiro-check-proxy))

  (extender/remove-proxy-listener! :shiro-check)

  )
