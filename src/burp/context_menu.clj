(ns burp.context-menu
  (:require [seesaw.core :as gui]
            [buddy.core.bytes :as bytes]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as base64]
            [burp.utils :as utils])
  (:import [burp
            IContextMenuInvocation
            IContextMenuFactory]
           ))

(defn get-invocation-context
  [invocation]
  (-> (.getInvocationContext invocation)
      utils/menu-invocation-context-inv))

(defn get-selected-messge
  [invocation]
  (.getSelectedMessages invocation))

(defn get-selected-text
  "获得选中的字符"
  [invocation]
  (when-let [sel (.getSelectionBounds invocation)]
    (when-let [msg (-> (get-selected-messge invocation)
                       first)]
      (let [data (if (#{:message-editor-request
                        :message-viewer-request}
                      (get-invocation-context invocation))
                   (.getRequest msg)
                   (.getResponse msg))
            [start end] sel]
        ;; (log (format "sel:[%d %d]" start end))
        (-> (bytes/slice data start end)
            (codecs/bytes->str))))))

(defn make-context-menu
  [supported-context gen-menu-items-fn]
  (reify IContextMenuFactory
    (createMenuItems [this invocation]
      (let [menu-ctx (get-invocation-context invocation)]
        (if (supported-context menu-ctx)
          (gen-menu-items-fn invocation)
          [])))))
