(ns burp-clj.message-viewer
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [seesaw.swingx :as guix]
            [seesaw.rsyntax :as rsyntax]
            [seesaw.font :as font]
            [seesaw.table :as table]
            [seesaw.bind :as bind]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.keymap :as keymap]
            [seesaw.border :as border]
            [burp-clj.utils :as utils]
            [burp-clj.helper :as helper]
            [burp-clj.syntax-editor :as syntax-editor]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.proxy :as proxy]
            [seesaw.core :as gui])
  (:import javax.swing.ComboBoxEditor
           java.awt.event.KeyEvent
           java.awt.Color
           ))

(defn get-filter-pred
  "如果是错误的过滤表达式则抛出异常,否则返回过滤表达式函数"
  [filter-exp]
  (utils/add-dep []) ;; 必须加载依赖,否则在awt线程中会执行失败！
  (let [exp (-> (format "(fn [msg] %s)" filter-exp)
                (load-string))]
    (exp {})
    exp))

(defn make-http-message-model
  [{:keys [filter-pred datas columns]}]
  (let [pred-fn (try (get-filter-pred filter-pred)
                     (catch Exception e
                       (constantly false)))
        pred (fn [data]
               (helper/with-exception-default nil
                 (pred-fn data)))]
    (table/table-model :columns columns
                       :rows (filter pred datas))))

(defn make-syntax-combox-editor
  "创建combobox使用的syntax editor"
  [syntax-text-area]
  (let [actions (atom #{})]
    (keymap/map-key syntax-text-area
                    "control ENTER" (fn [e]
                                      (doseq [a @actions]
                                        (.actionPerformed a e)))
                    :scope :self)
    (reify ComboBoxEditor
      (addActionListener [this listener]
        (swap! actions conj listener))
      (removeActionListener [this listener]
        (swap! actions disj listener))
      (getEditorComponent [this]
        syntax-text-area)
      (selectAll [this]
        (.selectAll syntax-text-area))
      (setItem [this obj]
        (.setText syntax-text-area obj))
      (getItem [this]
        (.getText syntax-text-area)))))

(defn make-ac-combox
  "创建编辑器带自动完成的combbox"
  [{:keys [setting-key auto-completion item-validation editor-options]
    :or {item-validation identity
         editor-options [:wrap-lines? true
                         :font (font/font :font :monospaced
                                          :size 20)
                         ]}}]
  (let [datas (extender/get-setting setting-key)
        cb (gui/combobox :model datas
                         :editable? true)
        model (.getModel cb)
        editor (apply syntax-editor/syntax-text-area
                      {:auto-completion auto-completion
                       :input-map {"control P" "caret-up"
                                   "control N" "caret-down"
                                   "control B" "caret-backward"
                                   "control F" "caret-forward"
                                   "control A" "caret-begin-line"
                                   "control E" "caret-end-line"
                                   "control D" "delete-next"
                                   "control K" "RTA.DeleteRestOfLineAction"
                                   "alt K" "RTA.DeleteLineAction"
                                   "alt B" "caret-previous-word"
                                   "alt F" "caret-next-word"
                                   }}
                      editor-options)
        combox-editor (make-syntax-combox-editor editor)]
    (->> (.getSize model)
         (.insertElementAt model "clear all"))
    (.addActionListener combox-editor
                        (gui/action
                         :name "check syntax"
                         :handler (fn [e]
                                    (let [txt (gui/text e)]
                                      (cond
                                        (empty? txt)
                                        (->> (border/line-border :color Color/RED)
                                             (.setBorder editor))

                                        (= (.getElementAt model 0) txt)
                                        (->> (border/empty-border)
                                             (.setBorder editor))

                                        (item-validation txt)
                                        (do
                                          (->> (border/line-border :color Color/GREEN)
                                               (.setBorder editor))
                                          (extender/update-setting! setting-key #(cons txt %1) )
                                          (.insertElementAt model txt 0)
                                          (.setSelectedItem model txt))

                                        :else
                                        (->> (border/line-border :color Color/RED)
                                             (.setBorder editor))
                                        )))))
    (gui/listen cb :selection
                (fn [e]
                  (let [exp (gui/selection cb)]
                    (log/info "cb selection:" exp)
                    (when (and (= exp "clear all")
                               (> (.getSize model) 1))
                      (log/info "clear all filter info:" setting-key)
                      (.removeAllElements model)
                      (extender/set-setting! setting-key '())
                      (.addElement model "clear all")))))
    (.setEditor cb combox-editor)
    cb))

(defn http-message-viewer
  "创建http消息查看器"
  [{:keys [columns datas setting-key auto-completion-words width height]
    :or {width 1000
         height 600
         auto-completion-words ["request"
                                "response"
                                "reverse"
                                "str/split"
                                "str/reverse"
                                "str/includes?"
                                "utils/try-parse-int"
                                "utils/try-parse-long"
                                "re-find"
                                "re-match"
                                "first"
                                "msg"]}}]
  (let [auto-completion-words (->> (first @datas)
                                   keys
                                   (map str)
                                   (concat  auto-completion-words))
        filter-cb (make-ac-combox {:setting-key setting-key
                                   :item-validation (fn [txt]
                                                      (try (get-filter-pred txt)
                                                           true
                                                           (catch Exception e
                                                             (gui/invoke-later
                                                              (gui/alert
                                                               (format "%s error filter expression:%s"
                                                                       txt
                                                                       e)))
                                                             false
                                                             )))
                                   :auto-completion {:use-parameter-assistance false
                                                     :trigger-key "control PERIOD"
                                                     :activate-delay 10
                                                     :init-words auto-completion-words}
                                   :editor-options [:syntax :clojure
                                                    :rows 3]
                                   })
        tbl (guix/table-x :id :http-message-table
                          :selection-mode :single
                          :model (make-http-message-model {:filter-pred (gui/selection filter-cb)
                                                           :datas @datas
                                                           :columns columns
                                                           }))
        req-resp-controller (helper/make-request-response-controller)]
    (helper/init req-resp-controller false)
    (gui/listen tbl :selection
                (fn [e]
                  (let [v (some->> (gui/selection tbl)
                                   (table/value-at tbl))]
                    ;; (log/info :table :selection "value:" v)
                    (helper/set-message req-resp-controller v)
                    )))
    (gui/listen filter-cb :selection
                (fn [e]
                  (log/info "change model:" (gui/selection e))
                  (->> (make-http-message-model {:filter-pred (gui/selection e)
                                                 :datas @datas
                                                 :columns columns})
                       (gui/config! tbl :model))))
    (bind/bind
     datas
     (bind/transform #(fn [new-datas]
                        (log/info "change model:" (gui/selection filter-cb))
                        (make-http-message-model {:filter-pred (gui/selection filter-cb)
                                                  :datas new-datas
                                                  :columns columns})))
     (bind/property tbl :model))
    (gui/top-bottom-split (mig-panel
                           :items [["Filter:"]
                                   [filter-cb
                                    "wrap, grow"]
                                   [(gui/scrollable tbl)
                                    "wrap, span, grow, width 100%, height 100%"]])
                          (gui/left-right-split
                           (-> (helper/get-request-editor req-resp-controller)
                               (.getComponent))
                           (-> (helper/get-response-editor req-resp-controller)
                               (.getComponent))
                           :divider-location 1/2)
                          :divider-location 2/3
                          :preferred-size [width :by height])))

