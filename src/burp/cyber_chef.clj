(ns burp.cyber-chef
  (:require [seesaw.core :as gui]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as base64]
            [clojure.java.browse :refer [browse-url]]
            [clojure.string :as str]
            [burp.context-menu :as context-menu]
            [burp.extender :as extender]
            [burp.utils :as utils]))

(defn browse-cyber-chef
  [input]
  (->> (base64/encode input)
       (codecs/bytes->str)
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
       (utils/log "selected text:" txt)
       [(gui/menu-item :text "CyberChef Magic"
                       :enabled? (not-empty txt)
                       :listen [:action (fn [e]
                                          (browse-cyber-chef txt))])]))))
