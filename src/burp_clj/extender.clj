(ns burp-clj.extender
  (:require [burp-clj.state :as state]
            [camel-snake-kebab.core :as csk]
            [cheshire.core :as json]
            [clojure.spec.alpha :as s]
            [burp-clj.specs :as specs]
            [taoensso.timbre :as log]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [camel-snake-kebab.core :as csk]
            [me.raynes.fs :as fs]
            [clojure.java.io :as io])
  (:refer-clojure :exclude [get])
  (:import [burp
            ITab
            IHttpService
            IHttpRequestResponse
            IMessageEditorController]))

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
        register-name-s (str "register" cb-name "!")
        register-name (csk/->kebab-case-symbol register-name-s)
        registered? (-> (str cb-name "-registered?")
                        csk/->kebab-case-symbol)
        remove-method (-> (str "remove" cb-name)
                          csk/->camelCaseSymbol)
        remove-name-s (str "remove" cb-name "!")
        remove-name (csk/->kebab-case-symbol remove-name-s)
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
         (if (~registered? k#)
           (log/warn ~register-name-s "already registered:" k#)
           (do
             (log/info ~register-name-s k#)
             (. (:extender @state/state) ~register-method cb#)
             (add-callback! ~cb-key k# cb#))))

       (defn ~remove-name [k#]
         (if-let [cb# (get-callback-obj ~cb-key k#)]
           (do
             (log/info ~remove-name-s k#)
             (. (:extender @state/state) ~remove-method cb#)
             (remove-callback! ~cb-key k#))
           (log/warn ~remove-name-s "not found:" k#)))

       (defn ~get-by-key [k#]
         (get-callback-obj ~cb-key k#))

       (defn ~get-all-name []
         (. (:extender @state/state) ~get-all-method))

       (defn ~remove-all-name []
         (log/info ~remove-all-name)
         (doseq [[k# obj#] (get-callbacks ~cb-key)]
           (. (:extender @state/state) ~remove-method obj#)
           (remove-callback! ~cb-key k#))))))

;; 鼠标右键上下文菜单
(defcallback ContextMenuFactory getContextMenuFactories)

;; 扩展状态
(defcallback ExtensionStateListener getExtensionStateListeners)

;; http事件
(defcallback HttpListener getHttpListeners)

;; intruder payload处理
(defcallback IntruderPayloadGeneratorFactory getIntruderPayloadGeneratorFactories)
(defcallback IntruderPayloadProcessor getIntruderPayloadProcessors)

;; 添加新的message editor tab
(defcallback MessageEditorTabFactory getMessageEditorTabFactories)

;; proxy事件
(defcallback ProxyListener getProxyListeners)

;; 扫描器处理
(defcallback ScannerCheck getScannerChecks)
(defcallback ScannerInsertionPointProvider getScannerInsertionPointProviders)
(defcallback ScannerListener getScannerListeners)

;; scope处理
(defcallback ScopeChangeListener getScopeChangeListeners)

;; session处理
(defcallback SessionHandlingAction getSessionHandlingActions)

(defn make-http-req
  ([^IHttpService service ^bytes req]
   (-> (get)
       (.makeHttpRequest service req)))
  ([^String host ^Integer port ^Boolean https ^bytes req]
   (-> (get)
       (.makeHttpRequest host port https req))))

(defn get-setting
  [k]
  (-> (get)
      (.loadExtensionSetting (str k))
      (edn/read-string)))

(defn set-setting!
  [k v]
  (-> (get)
      (.saveExtensionSetting (str k) (pr-str v))))

(defn update-setting!
  [k update-fn & args]
  (let [old-v (get-setting k)]
    (->> (apply update-fn old-v args)
         (set-setting! k))))

(defmacro defsetting
  [setting-k default-v & [set-arg-validate]]
  (let [sym (-> setting-k
                name
                symbol)
        get-fn (symbol (str "get-" sym))
        set-fn (symbol (str "set-" sym "!"))
        update-fn (symbol (str "update-" sym "!"))
        set-arg (symbol "v")
        init (gensym "init-setting-key")]
    `(do
       ;; set default value
       (defn ~get-fn
         []
         (defonce ~init (when (nil? (get-setting ~setting-k))
                          (log/info "init:" ~setting-k)
                          (set-setting! ~setting-k ~default-v)))
         (get-setting ~setting-k))

       (defn ~set-fn
         [~set-arg]
         ~(when set-arg-validate
            `{:pre [(~set-arg-validate ~set-arg)]})
         (set-setting! ~setting-k ~set-arg))

       (defn ~update-fn
         [update-fn# & args#]
         (apply update-setting! ~setting-k update-fn# args#)))))

(defn gen-config-path
  [path]
  (->> path
       (map csk/->snake_case_string)
       (str/join ".")))

(defn get-project-config
  "获取项目配置
  可以指定多个path
  path格式 [:project-options :connections :out-of-scope-requests] "
  [& paths]
  (let [paths (map gen-config-path paths)
        config (->> (into-array String paths)
                    (.saveConfigAsJson (get)))]
    (json/decode config csk/->kebab-case-keyword)))

(defn load-project-config
  [^String json-conf]
  (.loadConfigAsJson (get) json-conf))

(defn get-burp-clj-version
  []
  (-> (get)
      (.getBurp-CljVersion)))

(defn get-cookie-jar
  []
  (->> (get)
       (.getCookieJarContents)))

(defn get-extension-path
  []
  (-> (get)
      (.getExtensionFilename)))

(defn add-site-map
  [^IHttpRequestResponse req-resp]
  (-> (get)
      (.addToSiteMap req-resp)))

(defn get-site-map
  [url]
  (-> (get)
      (.getSiteMap url)))

(defn create-message-editor
  "创建一个burp-clj MessageEditor"
  [^IMessageEditorController controller ^Boolean editable]
  (-> (get)
      (.createMessageEditor controller editable)))

(defn create-text-editor
  "创建一个burp-clj TextEditor"
  []
  (-> (get)
      (.createTextEditor)))

(defn customize-ui-comp!
  "对`comp` ui组件使用burp-clj的ui style"
  [comp]
  (-> (get)
      (.customizeUiComponent comp)))

(defn create-burp-collaborator-client
  []
  (-> (get)
      (.createBurpCollaboratorClientContext)))

(defn make-tab
  [caption ui-comp]
  (reify ITab
    (getTabCaption [_]
      caption)
    (getUiComponent [_]
      ui-comp)))

(defn add-tab!
  "添加tab，返回添加后的tab"
  ([caption ui-comp]
   (let [tab (make-tab caption ui-comp)]
     (customize-ui-comp! ui-comp)
     (add-tab! tab)))
  ([^ITab tab]
   (-> (get)
       (.addSuiteTab tab))
   tab))

(defn remove-tab!
  [^ITab tab]
  (-> (get)
      (.removeSuiteTab tab)))

(defn register-add-tab!
  [k {:keys [captain view] :as tab}]
  {:pre (s/valid? ::specs/tab tab)}
  (let [tab (add-tab! captain view)]
    (add-callback! :tabs k tab)))

(defn register-remove-tab!
  [k]
  (when-let [tab (get-callback-obj :tabs k)]
    (remove-tab! tab)
    (remove-callback! :tabs k)))

(defn exit-suit
  [prompt]
  (-> (get)
      (.exitSuite prompt)))

(defn get-proxy-history
  []
  (-> (get)
      (.getProxyHistory)))

(defn get-user-config
  [& paths]
  (with-open [rdr (-> (get)
                      (.saveConfigAsJson (into-array String paths))
                      (.getBytes)
                      (java.io.ByteArrayInputStream.)
                      io/reader)]
    (json/decode-stream rdr csk/->kebab-case-keyword)))

(defn add-scope!
  [url]
  (-> (get)
      (.includeInScope url)))

(defn in-scope?
  [url]
  (-> (get)
      (.isInScope url)))

