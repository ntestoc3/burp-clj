(ns burp-clj.cyber-chef
  (:require [seesaw.core :as gui]
            [clojure.java.browse :refer [browse-url]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]))

(defn browse-cyber-chef
  [input]
  (->> (helper/base64-encode input)
       (str "https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=" )
       browse-url))

(def menu-context #{:message-editor-request
                    :message-editor-response
                    :message-viewer-request
                    :message-viewer-response})


(defn cyber-chef-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     (let [txt (context-menu/get-selected-text invocation)]
       (log/info "cyber-chef selected text:" txt)
       [(gui/menu-item :text "CyberChef Magic"
                       :enabled? (not-empty txt)
                       :listen [:action (fn [e]
                                          (browse-cyber-chef txt))])]))))
