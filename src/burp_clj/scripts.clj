(ns burp-clj.scripts
  (:require [version-clj.core :as version]
            [me.raynes.fs :as fs]
            [clojure.spec.alpha :as s]
            [taoensso.timbre :as log]
            [burp-clj.extension-state :refer [make-unload-callback]]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]
            [burp-clj.specs :as specs]
            [burp-clj.version :refer [get-version]]
            [burp-clj.utils :as utils]))

(def db (atom {}))

(defn get-script-sources
  "获取所有script sources"
  []
  (get @db :source))

(defn set-script-sources
  "设置sctipt sources"
  [sources]
  (swap! db assoc :source sources))

(defn add-script-source!
  "添加脚本源，可以是git地址，或者目录"
  [source]
  {:pre [(s/valid? ::specs/script-source source)]}
  (swap! db update :source conj source))

(defn remove-script-source!
  [source]
  (swap! db update :source (fn [v]
                             (remove #(= source %) v))))

(defn- load-script-file
  [clj]
  (log/info :load-script-file clj)
  (helper/with-exception-default
    (log/error :load-script-file clj)
    (load-file clj)))

(defn- load-dir-scripts
  "加载一个文件下的所有clj文件"
  [dir]
  (utils/add-cp dir)
  (fs/with-cwd dir
    (doseq [clj (->> (-> (fs/file dir)
                         (fs/glob "*.clj"))
                     (map str))]
      (load-script-file clj))))

(defn- load-scripts!
  "加载source下的脚本文件"
  [type target]
  (case type
    :git
    (-> (utils/git-checkout target)
        load-dir-scripts)

    :file
    (load-dir-scripts target)

    (log/warn :load-scripts! "unsupport type:" type)))

(defn get-scripts
  []
  (:scripts @db))

(defn get-script
  [script-k]
  (get-in @db [:scripts script-k]))

(defn get-callbacks
  [callbacks-k]
  (get @db callbacks-k))

(defn- add-script!
  [k info]
  (let [callback-k (if (get-script k)
                     ;; 如果是已有的script重新加载，则调用script-state-change-callback
                     :script-state-change-callback
                     :script-add-callback)]
    (swap! db update :scripts assoc k info)
    (doseq [cb (get-callbacks callback-k)]
      (cb k info))))

(defn- set-script-running!
  [script-k running]
  (swap! db update :scripts assoc-in [script-k :running] running)
  (doseq [cb (get-callbacks :script-state-change-callback)]
    (cb script-k (get-script script-k))))

(defn- remove-all-script!
  []
  (swap! db assoc :scripts {})
  (doseq [cb (get-callbacks :scripts-clear-callback)]
    (cb)))

(defn reg-script-add-callback
  "注册添加script的回调函数

  `f` 回调函数，添加script时调用(f script-k script-info)"
  [f]
  (swap! db update :script-add-callback conj f))

(defn reg-script-state-change-callback
  "注册script状态更新的回调函数

  `f` 回调函数，script状态更新时调用(f script-k script-info)"
  [f]
  (swap! db update :script-state-change-callback conj f))

(defn reg-scripts-clear-callback
  "注册清除script的回调函数

  `f` 回调函数，无参数，清除全部scripts时调用"
  [f]
  (swap! db update :scripts-clear-callback conj f))

(defn reg-scripts-unload-callback
  "注册script卸载回调函数，所有脚本卸载时调用

  `f` 回调函数，无参数，卸载所有scripts时调用"
  [f]
  (swap! db update :scripts-unload-callback conj f))

;;;;; script
(defn enable-script!
  [script-k]
  (when-let [{:keys [name
                     version
                     enable-callback
                     context-menu
                     http-listener
                     intruder-payload-generator
                     intruder-payload-processor
                     message-editor-tab
                     proxy-listener
                     scanner-check
                     scanner-insertion-point-provider
                     scanner-listener
                     scope-change-listener
                     session-handling-action
                     tab]
              :as script-info} (get-script script-k)]
    (when-not (:running script-info)
      (helper/with-exception-default nil
        (log/info :enable-script! script-k name version)
        (when context-menu
          (doseq [[k v] context-menu]
            (extender/register-context-menu-factory! k v)))

        (when http-listener
          (doseq [[k v] http-listener]
            (extender/register-http-listener! k v)))

        (when intruder-payload-generator
          (doseq [[k v] intruder-payload-generator]
            (extender/register-intruder-payload-generator-factory! k v)))

        (when intruder-payload-processor
          (doseq [[k v] intruder-payload-processor]
            (extender/register-intruder-payload-processor! k v)))

        (when message-editor-tab
          (doseq [[k v] message-editor-tab]
            (extender/register-message-editor-tab-factory! k v)))

        (when proxy-listener
          (doseq [[k v] proxy-listener]
            (extender/register-proxy-listener! k v)))

        (when scanner-check
          (doseq [[k v] scanner-check]
            (extender/register-scanner-check! k v)))

        (when scanner-insertion-point-provider
          (doseq [[k v] scanner-insertion-point-provider]
            (extender/register-scanner-insertion-point-provider! k v)))

        (when scanner-listener
          (doseq [[k v] scanner-listener]
            (extender/register-scanner-listener! k v)))

        (when scope-change-listener
          (doseq [[k v] scope-change-listener]
            (extender/register-scope-change-listener! k v)))

        (when session-handling-action
          (doseq [[k v] session-handling-action]
            (extender/register-session-handling-action! k v)))

        (when tab
          (doseq [[k v] tab]
            (extender/register-add-tab! k v))
          #_(helper/switch-clojure-plugin-tab))

        (when enable-callback
          (log/info :enable-script! script-k "run enable-callback" )
          (enable-callback script-info))

        (set-script-running! script-k true)))))

(defn disable-script!
  [script-k]
  (when-let [{:keys [name
                     version
                     disable-callback
                     context-menu
                     http-listener
                     intruder-payload-generator
                     intruder-payload-processor
                     message-editor-tab
                     proxy-listener
                     scanner-check
                     scanner-insertion-point-provider
                     scanner-listener
                     scope-change-listener
                     session-handling-action
                     tab
                     ]
              :as script-info} (get-script script-k)]
    (when (:running script-info)
      (helper/with-exception-default
        nil
        (log/info :disable-script! script-k name version)
        (when disable-callback
          (log/info :disable-script! script-k "run disable-callback" )
          (disable-callback script-info))

        (when context-menu
          (doseq [k (keys context-menu)]
            (extender/remove-context-menu-factory! k)))

        (when http-listener
          (doseq [k (keys http-listener)]
            (extender/remove-http-listener! k)))

        (when intruder-payload-generator
          (doseq [k (keys intruder-payload-generator)]
            (extender/remove-intruder-payload-generator-factory! k)))

        (when intruder-payload-processor
          (doseq [k (keys intruder-payload-processor)]
            (extender/remove-intruder-payload-processor! k)))

        (when message-editor-tab
          (doseq [k (keys message-editor-tab)]
            (extender/remove-message-editor-tab-factory! k)))

        (when proxy-listener
          (doseq [k (keys proxy-listener)]
            (extender/remove-proxy-listener! k)))

        (when scanner-check
          (doseq [k (keys scanner-check)]
            (extender/remove-scanner-check! k)))

        (when scanner-insertion-point-provider
          (doseq [k (keys scanner-insertion-point-provider)]
            (extender/remove-scanner-insertion-point-provider! k)))

        (when scanner-listener
          (doseq [k (keys scanner-listener)]
            (extender/remove-scanner-listener! k)))

        (when scope-change-listener
          (doseq [k (keys scope-change-listener)]
            (extender/remove-scope-change-listener! k)))

        (when session-handling-action
          (doseq [k (keys session-handling-action)]
            (extender/remove-session-handling-action! k)))

        (when tab
          (doseq [k (keys tab)]
            (extender/register-remove-tab! k)))

        (set-script-running! script-k false)))))

(defn reload-script!
  [script-k]
  (utils/add-dep [])
  (let [info (get-script script-k)
        running (:running info)]
    (when running
      (disable-script! script-k))
    (load-script-file (:file info))
    (when running
      (enable-script! script-k))))

(defn reg-script!
  "注册一个script,成功返回true"
  [k info]
  {:pre [(s/valid? ::specs/script-info info)]}
  (let [old-info (get-script k)]
    ;; 如果有同名的脚本，并且新注册的版本号小于旧的版本号，则不更新
    (cond
      (and old-info
           (neg? (version/version-compare (:version info)
                                          (:version old-info))))
      (log/warn :reg-script! k "already exist version:" (:version info))

      ;; 或者script需要的burp-clj版本号大于当前的burp-script版本号，也不更新
      (pos? (version/version-compare (:min-burp-clj-version info)
                                     (get-version)))
      (log/warn :reg-script! k
                "min-burp-clj-version bigger than current burp-clj version: "
                (get-version))

      :else
      (do
        (when (:running old-info)
          (disable-script! k))
        (->> (assoc info
                    :running false
                    :file *file*) ;; 初始化运行状态为false
             (add-script! k))
        (when (:running old-info)
          (enable-script! k))
        true))))

(defn get-running-scripts
  []
  (->> (:scripts @db)
       (filter (comp :running val))
       keys
       vec))

(defn unreg-all-script!
  []
  (when-let [running (get-running-scripts)]
    (extender/set-setting! :script/running running)
    (doseq [s running]
      (disable-script! s)))
  (remove-all-script!))

(defn load-sources-with-running!
  [running]
  ;; 调用add-dep修正classloader
  (utils/add-dep [])
  (doseq [[type target] (->> (:source @db)
                             (map #(s/conform ::specs/script-source %)))]
    (helper/with-exception-default
      nil
      (load-scripts! type target)))
  (doseq [s running]
    (enable-script! s)))

(defn reload-sources!
  []
  (unreg-all-script!)
  (-> (or (extender/get-setting :script/running)
          [])
      load-sources-with-running!))

(defn unload!
  []
  (doseq [cb (get-callbacks :scripts-unload-callback)]
    (cb))
  (unreg-all-script!)
  (extender/set-setting! :script/sources (get-script-sources))
  (shutdown-agents))

(defn init!
  []
  (let [sources (or (extender/get-setting :script/sources)
                    [])
        running (or (extender/get-setting :script/running)
                    [])]
    (log/info :scripts-init! "sources:" sources)
    (set-script-sources sources)
    (load-sources-with-running! running)
    (extender/register-extension-state-listener! :script/source-manager
                                                 (make-unload-callback unload!))))

(comment

  (add-script-source! "/mnt/data/OCaml64/home/netstoc3/code/burp-scripts/")

  (reload-sources!)


  (add-script-source! "https://github.com/ntestoc3/burp-scripts")


  )
