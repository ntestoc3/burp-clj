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

(def burp-clj-clj-version "0.0.1")

(def ^:private db (atom {}))

(comment
  {:name "script-name"
   :version "1.0"
   :min-burp-clj-version "1.0"
   :enable-callback :reg-fn
   :disable-callback :unreg-fn
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

(defn add-script-source!
  [source]
  {:pre [(s/valid? ::specs/script-source source)]}
  (swap! db update :source conj source))

(defn remove-script-source!
  [source]
  (swap! db update :source dissoc source))

(defn load-dir-scripts
  [dir]
  (utils/add-cp dir)
  (fs/with-cwd dir
    (doseq [clj (->> (-> (fs/file dir)
                         (fs/glob "*.clj"))
                     (map str))]
      (log/info :load-script clj)
      (load-file clj))))

(defn load-scripts!
  [type target]
  (case type
    :git
    (-> (utils/git-checkout target)
        load-dir-scripts)

    :file
    (load-dir-scripts target)

    (log/warn :load-scripts! "unsupport type:" type)))

(defn reload-sources!
  []
  (doseq [[type target] (->> (:source @db)
                             (map #(s/conform ::specs/script-source %)))]
    (load-scripts! type target)))

(defn get-all-scripts
  []
  (:scripts @db))

(defn get-script
  [script-name]
  (->> (get-all-scripts)
       (take-while #(= script-name (:name %)))))

(defn reg-script!
  "注册一个script"
  [info]
  {:pre [(s/valid? ::specs/script-info info)]}
  (let [old-info (get-script (:name info))]
    ;; 如果有同名的脚本，并且新注册的版本号小于旧的版本号，则不更新
    (if (and old-info
             (neg? (version/version-compare (:version info)
                                            (:version old-info))))
      (log/warn :reg-script! (:name info)
                "already exist version:" (:version info))
      ;; 或者script需要的burp-clj版本号大于当前的burp-script版本号，也不更新
      (if (pos? (version/version-compare (:min-burp-clj-version info)
                                         (get-version)))
        (log/warn :reg-script! (:name info)
                  "min-burp-clj-version bigger than current burp-clj version: "
                  (get-version))
        (swap! db update :scripts conj info)))))

(defn enable-script!
  [{:keys [name
           enable-callback
           content-menu
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
    :as script-info}]
  (log/info :enable-script! name)
  (when content-menu
    (doseq [[k v] content-menu]
      (extender/register-context-menu-factory! k v)))
  (when extension-state-listener
    (doseq [[k v] extension-state-listener]
      (extender/register-extension-state-listener! k v)))
  (when http-listener
    (doseq [[k v] http-listener]
      (extender/register-http-listener! k v)))

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
      (extender/add-tab! k v)))
  )


(comment

  (add-script-source! "/mnt/data/OCaml64/home/netstoc3/code/burp-scripts/")

  (add-script-source! "https://github.com/ntestoc3/burp-scripts")


  )
