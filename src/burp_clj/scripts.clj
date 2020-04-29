(ns burp-clj.scripts
  (:require [version-clj.core :as version]
            [me.raynes.fs :as fs]
            [clojure.spec.alpha :as s]
            [taoensso.timbre :as log]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]
            [burp-clj.specs :as specs]
            [burp-clj.version :refer [get-version]]
            [burp-clj.utils :as utils]))

(def db (atom {}))

(defn add-script-source!
  "添加脚本源，可以是git地址，或者目录"
  [source]
  {:pre [(s/valid? ::specs/script-source source)]}
  (swap! db update :source conj source))

(defn remove-script-source!
  [source]
  (swap! db update :source dissoc source))

(defn- load-dir-scripts
  "加载一个文件下的所有clj文件"
  [dir]
  (utils/add-cp dir)
  (fs/with-cwd dir
    (doseq [clj (->> (-> (fs/file dir)
                         (fs/glob "*.clj"))
                     (map str))]
      (log/info :load-script clj)
      (load-file clj))))

(defn load-scripts!
  "加载source下的脚本文件"
  [type target]
  (case type
    :git
    (-> (utils/git-checkout target)
        load-dir-scripts)

    :file
    (load-dir-scripts target)

    (log/warn :load-scripts! "unsupport type:" type)))

(defn get-all-scripts
  []
  (:scripts @db))

(defn get-script
  [script-k]
  (get-in @db [:scripts script-k]))

(defn set-script-running!
  [script-k running]
  (swap! db update assoc-in [:scripts :running] running))

(defn enable-script!
  [script-k]
  (when-let [{:keys [name
                     version
                     enable-callback
                     context-menu
                     extension-state-listener
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
    (log/info :enable-script! script-k name version)
    (when context-menu
      (doseq [[k v] context-menu]
        (extender/register-context-menu-factory! k v)))

    (when extension-state-listener
      (doseq [[k v] extension-state-listener]
        (extender/register-extension-state-listener! k v)))

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

    (when tab
      (doseq [[k v] tab]
        (extender/register-add-tab! k v)))

    (when enable-callback
      (log/info :enable-script! script-k "run enable-callback" )
      (enable-callback script-info))

    (set-script-running! script-k true)
    true))

(defn disable-script!
  [script-k]
  (when-let [{:keys [name
                     version
                     disable-callback
                     context-menu
                     extension-state-listener
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
    (helper/with-exception-default
      nil
      (log/info :disable-script! script-k name version)
      (when disable-callback
        (log/info :disable-script! script-k "run disable-callback" )
        (disable-callback script-info))

      (when context-menu
        (doseq [k (keys context-menu)]
          (extender/remove-context-menu-factory! k)))

      (when extension-state-listener
        (doseq [k (keys extension-state-listener)]
          (extender/remove-extension-state-listener! k)))

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

      (when tab
        (doseq [k (keys tab)]
          (extender/register-remove-tab! k)))

      (set-script-running! script-k false)
      true
      )))

(defn reg-script!
  "注册一个script,成功返回true"
  [k info]
  {:pre [(s/valid? ::specs/script-info info)]}
  (let [old-info (get-script k)]
    ;; 如果有同名的脚本，并且新注册的版本号小于旧的版本号，则不更新
    (if (and old-info
             (neg? (version/version-compare (:version info)
                                            (:version old-info))))
      (log/warn :reg-script! k "already exist version:" (:version info))
      ;; 或者script需要的burp-clj版本号大于当前的burp-script版本号，也不更新
      (if (pos? (version/version-compare (:min-burp-clj-version info)
                                         (get-version)))
        (log/warn :reg-script! k
                  "min-burp-clj-version bigger than current burp-clj version: "
                  (get-version))
        (do (->> (assoc info :running false) ;; 初始化运行状态为false
                 (swap! db update :scripts assoc k))
            true)))))

(defn unreg-all-script!
  []
  (doseq [s (->> (:scripts @db)
                 (filter :running))]
    (disable-script! s))
  (swap! db assoc :scripts {}))

(defn reload-sources!
  []
  (unreg-all-script!)
  (doseq [[type target] (->> (:source @db)
                             (map #(s/conform ::specs/script-source %)))]
    (helper/with-exception-default
      nil
      (load-scripts! type target))))

(comment

  (add-script-source! "/mnt/data/OCaml64/home/netstoc3/code/burp-scripts/")

  (reload-sources!)


  (add-script-source! "https://github.com/ntestoc3/burp-scripts")


  )
