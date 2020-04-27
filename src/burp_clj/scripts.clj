(ns burp-clj.scripts
  (:require [version-clj.core :as version]
            [burp-clj.utils :as utils]))

(def burp-clj-clj-version "0.0.1")

(def ^:private db (atom {}))

(comment
  {:name "script-name"
   :version "1.0"
   :min-burp-clj-clj-version "1.0"
   :enable :reg-fn
   :disable :unreg-fn
   :content-menus []
   :extension-state-listeners []
   :http-listeners []
   :intruder-payload-generators []
   :intruder-payload-processors []
   :messaage-editor-tabs []
   :proxy-listeners []
   :scanner-checks []
   :scanner-insertion-point-providers []
   :scanner-listeners []
   :scope-change-listeners []
   :session-handling-actions []
   :tabs []
   }

  )


(defn reg-script!
  "注册一个script"
  [info]
  (update db :scripts conj info))

(defn add-script-source!
  [source]
  (update db :source conj source))

(defn add-scripts!
  []
  )

