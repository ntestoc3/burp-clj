(ns burp-clj.validate
  (:require [burp-clj.utils :as utils]
            [clojure.tools.gitlibs :as gitlib]
            [camel-snake-kebab.core :as csk]
            [clojure.string :as str])
  (:import [burp
            IContextMenuFactory
            IExtensionStateListener
            IHttpListener
            IIntruderPayloadGeneratorFactory
            IIntruderPayloadProcessor
            IMessageEditorTabFactory
            IProxyListener
            IScannerCheck
            IScannerInsertionPointProvider
            IScannerListener
            IScopeChangeListener
            ISessionHandlingAction
            ITab]))

(defn valid-git-source?
  [url]
  (try (gitlib/resolve url "master")
       true
       (catch Exception _ false)))

(defn valid-port?
  [^Integer port]
  (< 0 port 65536))

(defmacro defvalid
  [name class]
  (let [valid-fn (-> (str "valid-" name "?")
                     csk/->kebab-case-symbol)]
    `(defn ~valid-fn
       [inst#]
       (instance? ~class inst#))))

(defvalid swing-comp java.awt.Component)
(defvalid ContextMenuFactory IContextMenuFactory)
(defvalid ExtensionStateListener IExtensionStateListener)
(defvalid HttpListener IHttpListener)
(defvalid IntruderPayloadGeneratorFactory IIntruderPayloadGeneratorFactory)
(defvalid IntruderPayloadProcessor IIntruderPayloadProcessor)
(defvalid MessageEditorTabFactory IMessageEditorTabFactory)
(defvalid ProxyListener IProxyListener)
(defvalid ScannerCheck IScannerCheck)
(defvalid ScannerInsertionPointProvider IScannerInsertionPointProvider)
(defvalid ScannerListener IScannerListener)
(defvalid ScopeChangeListener IScopeChangeListener)
(defvalid SessionHandlingAction ISessionHandlingAction)
(defvalid tab ITab)



