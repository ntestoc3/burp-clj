(ns burp.extender
  (:require [burp.state :as state]
            [camel-snake-kebab.core :as csk])
  (:refer-clojure :exclude [get]))

(defn set!
  [callbacks]
  (swap! state/state assoc :extender callbacks))

(defn get []
  (:extender @state/state))

(defn- add-callback!
  "添加回调注册
  `class-k` 类别的key
  `cb-k` 回调的key
  `cb-obj` 回调对象"
  [class-k cb-k cb-obj]
  (swap! state/state update class-k assoc cb-k cb-obj))

(defn- remove-callback!
  [class-k cb-k]
  (swap! state/state update class-k dissoc cb-k))

(defn get-callback-obj
  "获取回调对象"
  [class-k cb-k]
  (get-in @state/state [class-k cb-k]))

(defn get-callbacks
  [class-k]
  (get @state/state class-k))

(defmacro defcallback
  [callback get-cb-method-name]
  (let [cb-name (name callback)
        cb-key (csk/->kebab-case-keyword callback)
        register-method (-> (str "register" callback)
                            csk/->camelCaseSymbol)
        register-name (-> (str "register" cb-name "!")
                          csk/->kebab-case-symbol)
        registered? (-> (str cb-name "-registered?")
                        csk/->kebab-case-symbol)
        remove-method (-> (str "remove" cb-name)
                          csk/->camelCaseSymbol)
        remove-name (-> (str "remove" cb-name "!")
                        csk/->kebab-case-symbol)
        get-by-key (-> (str "get" cb-name "ByKey")
                       csk/->kebab-case-symbol)
        get-all-method get-cb-method-name
        get-all-name (-> (str "get-all-" cb-name)
                         csk/->kebab-case-symbol)
        remove-all-name (-> (str "remove-all-" cb-name "!")
                            csk/->kebab-case-symbol)]
    `(do
       (defn ~registered? [k#]
         (-> (get-callback-obj ~cb-key k#)
             boolean))

       (defn ~register-name [k# cb#]
         (when-not (~registered? k#)
           (. (:extender @state/state) ~register-method cb#)
           (add-callback! ~cb-key k# cb#)))

       (defn ~remove-name [k#]
         (when-let [cb# (get-callback-obj ~cb-key k#)]
           (. (:extender @state/state) ~remove-method cb#)
           (remove-callback! ~cb-key k#)))

       (defn ~get-by-key [k#]
         (get-callback-obj ~cb-key k#))

       (defn ~get-all-name []
         (. (:extender @state/state) ~get-all-method))

       (defn ~remove-all-name []
         (doseq [[k# obj#] (get-callbacks ~cb-key)]
           (. (:extender @state/state) ~remove-method obj#)
           (remove-callback! ~cb-key k#))))))

(defcallback ContextMenuFactory getContextMenuFactories)
(defcallback ExtensionStateListener getExtensionStateListeners)
(defcallback HttpListener getHttpListeners)
(defcallback IntruderPayloadGeneratorFactory getIntruderPayloadGeneratorFactories)
(defcallback IntruderPayloadProcessor getIntruderPayloadProcessors)
(defcallback MessageEditorTabFactory getMessageEditorTabFactories)
(defcallback ProxyListener getProxyListeners)
(defcallback ScannerCheck getScannerChecks)
(defcallback ScannerInsertionPointProvider getScannerInsertionPointProviders)
(defcallback ScannerListener getScannerListeners)
(defcallback ScopeChangeListener getScopeChangeListeners)
(defcallback SessionHandlingAction getSessionHandlingActions)
