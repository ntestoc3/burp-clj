(ns burp-clj.core
  (:require [burp-clj.extender :as extender]
            [burp-clj.ui :as ui]
            [burp-clj.version :as version]
            [burp-clj.helper :as helper]
            [burp-clj.scripts :as script]
            [burp-clj.utils :as utils]
            [taoensso.timbre :as log]
            )
  (:gen-class)
  )

(defn logger
  [data]
  (let [{:keys [output_ level error-level?]} data
        formatted-output-str (force output_)]
    (if error-level?
      (helper/alert formatted-output-str)
      (helper/log formatted-output-str))))


;;; 必须存在，extension加载时执行
(defn register
  "注册回调"
  [cbs]
  (.setExtensionName cbs "Clojure Plugin")
  (extender/set! cbs)
  (utils/add-dep []) ;; 设置class loader,重复加载插件，classpath会变
  (utils/log-time-format!)

  (utils/log-to-fn! :plugin-log logger)

  (log/info :register "clojure plugin version:" (version/get-version))

  (script/init!)

  (extender/add-tab! "Clojure Plugin" (ui/make-view))

  (log/info :register "ok!"))


(comment
  (def tab (ui/make-view))

  )
