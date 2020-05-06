(ns burp-clj.message-editor
  (:require [burp-clj.helper :as helper])
  (:import [burp
            IMessageEditorTab
            IMessageEditorTabFactory]))

(defn make-message-editor-tab
  "创建一个message-editor-tab
  `make-fn` 参数为[message-editor-controller editable]"
  [make-fn]
  (reify IMessageEditorTabFactory
    (createNewInstance [this controller editable]
      (make-fn controller editable))))

