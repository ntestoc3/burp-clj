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
            [seesaw.color :as color]
            [burp-clj.utils :as utils]
            [burp-clj.helper :as helper]
            [burp-clj.syntax-editor :as syntax-editor]
            [burp-clj.extender :as extender]
            [burp-clj.filter-exp :as filter-exp]
            [seesaw.core :as gui]
            [clojure.set :as set])
  (:import javax.swing.ComboBoxEditor
           java.awt.event.KeyEvent
           java.awt.Color
           javax.swing.table.DefaultTableCellRenderer))


(defn get-filter-pred [txt]
  (let [exp (filter-exp/parse txt)]
    (if (filter-exp/failed? exp)
      (throw (ex-info (filter-exp/error-msg exp :html true) exp))
      #(filter-exp/eval %1 exp))))

(defn make-filter-data-fn [pred]
  (let [pred-fn (if (or (nil? pred)
                        (empty? (str/trim pred)))
                  identity
                  (try (get-filter-pred pred)
                       (catch Exception e
                         (constantly false))))]
    (fn [data]
      (helper/with-exception-default nil
        (pred-fn data)))))

(defn make-http-message-model
  [{:keys [filter-pred datas columns]}]
  (let [filter-fn (make-filter-data-fn filter-pred)]
    (table/table-model :columns columns
                       :rows (filter filter-fn datas))))

(defn make-syntax-combox-editor
  "创建combobox使用的syntax editor"
  [syntax-text-area]
  (let [actions (atom #{})]
    (keymap/map-key syntax-text-area
                    "ENTER" (fn [e]
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
    :or {item-validation identity}}]
  (let [datas (cons "" (extender/get-setting setting-key))
        cb (gui/combobox :model datas
                         :editable? true)
        model (.getModel cb)
        editor-options (merge {:font (font/font :font :monospaced
                                                :size 20)
                               :anti-aliasing? true
                               :highlight-current-line? false
                               }
                              editor-options)
        editor (apply syntax-editor/syntax-text-area
                      {:auto-completion auto-completion
                       :key-maps {"control B" "caret-backward"
                                  "control F" "caret-forward"
                                  "control A" "caret-begin-line"
                                  "control E" "caret-end-line"
                                  "control D" "delete-next"
                                  "control K" "RTA.DeleteRestOfLineAction"
                                  "alt K" "RTA.DeleteLineAction"
                                  "alt B" "caret-previous-word"
                                  "alt F" "caret-next-word"
                                  }}
                      (apply concat editor-options))
        combox-editor (make-syntax-combox-editor editor)]
    (->> (.getSize model)
         (.insertElementAt model "clear all..."))
    (.addActionListener combox-editor
                        (gui/action
                         :name "check syntax"
                         :handler (fn [e]
                                    (let [txt (gui/text e)]
                                      (cond
                                        (empty? (str/trim txt))
                                        (->> (border/line-border :color Color/BLACK)
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
                    (when (and (= exp "clear all...")
                               (> (.getSize model) 1))
                      (log/info "clear all filter info:" setting-key)
                      (.removeAllElements model)
                      (extender/set-setting! setting-key '())
                      (.addElement model "")
                      (.addElement model "clear all...")))))
    (.setEditor cb combox-editor)
    cb))

(defn- diff-datas
  "根据`key-fn`获取ys比xs多的数据"
  [xs ys key-fn]
  (let [ks (set/difference
            (set (map key-fn (vec ys)))
            (set (map key-fn (vec xs))))]
    (filter #(ks (key-fn %1)) ys)))

(defn cell-render []
  (proxy [DefaultTableCellRenderer] []
    (getTableCellRendererComponent
      [tbl
       ^java.lang.Object value
       ^java.lang.Boolean selected
       ^java.lang.Boolean has-focus
       ^java.lang.Integer row
       ^java.lang.Integer column]
      (let [c (proxy-super getTableCellRendererComponent tbl value selected has-focus row column)
            v (table/value-at tbl row)]
        (when-some [bg (:background v)]
          (.setBackground c (color/color bg)))
        (when-some [fg (:foreground v)]
          (.setForeground c (color/color fg)))
        c))))

(defn http-message-viewer
  "创建http消息查看器
  datas 支持添加和清空，不支持删除; 添加时会忽略重复的key
  :key-fn 获取datas数据唯一键的函数"
  [{:keys [columns datas setting-key ac-words width height key-fn]
    :or {width 1000
         key-fn :index
         height 600}}]
  (let [auto-completion-words (concat ["contains"
                                       "in"
                                       "matches"]
                                      (map filter-exp/->filter-obj-name ac-words))
        filter-cb (make-ac-combox {:setting-key setting-key
                                   :item-validation (fn [txt]
                                                      (try (get-filter-pred txt)
                                                           true
                                                           (catch Exception e
                                                             (gui/invoke-later
                                                              (gui/alert (ex-message e)))
                                                             false)))
                                   :auto-completion {:provider {:ac-words auto-completion-words
                                                                :activation-rules "."}
                                                     :parameter-assistance? false
                                                     :auto-activation? true
                                                     :trigger-key "TAB"
                                                     :delay 10}
                                   :editor-options {:syntax :c}})
        tbl (guix/table-x :id :http-message-table
                          :selection-mode :single
                          :model (make-http-message-model {:filter-pred nil
                                                           :datas @datas
                                                           :columns columns}))
        req-resp-controller (helper/make-request-response-controller)]
    (.setDefaultRenderer tbl java.lang.Object (cell-render))
    (.setDefaultRenderer tbl java.lang.Number (cell-render))
    (helper/init req-resp-controller false)
    (gui/listen tbl :selection
                (fn [e]
                  (when-not (.getValueIsAdjusting e)
                    (let [v (some->> (gui/selection tbl)
                                     (table/value-at tbl))]
                      (log/info :table :selection "sel:" (gui/selection tbl) "value index:" (:index v))
                      (helper/set-message req-resp-controller v)))))
    (gui/listen filter-cb :selection
                (fn [e]
                  ;; (log/info "change model:" (gui/selection e))
                  (->> (make-http-message-model {:filter-pred (gui/selection e)
                                                 :datas @datas
                                                 :columns columns})
                       (gui/config! tbl :model))))
    (add-watch datas :http-message-viewer
               (fn [_ _ old-v new-v]
                 (log/info "watch run.." )
                 (try (if (empty? new-v)
                        (table/clear! tbl)
                        (when-some [vs (diff-datas old-v new-v key-fn)]
                          (let [filter-fn (-> (gui/text filter-cb)
                                              (doto (print " [filter]"))
                                              (make-filter-data-fn))]
                            (doseq [v (filter filter-fn vs)]
                              (log/info "http viewer add new row:" (key-fn v))
                              (gui/invoke-later
                               (table/add! tbl v))))))
                      (catch Exception e
                        (log/error "error change http viewer data:" e)))))
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

(comment

  (def hs (extender/get-proxy-history))

  (def datas (map-indexed (fn [idx v]
                            (let [info (helper/parse-http-req-resp v)]
                              (assoc info :index idx
                                     :foreground :green
                                     :background :red))) hs))

  (def cols-info [{:key :index :text "#" :class java.lang.Long}
                  {:key :host :text "Host" :class java.lang.String}
                  {:key :request/url :text "URL" :class java.lang.String}
                  {:key :response/status :text "Resp.Status" :class java.lang.Long}
                  {:key :response.headers/content-length :text "Resp.Len" :class java.lang.String}
                  {:key :response.headers/content-type :text "Resp.type" :class java.lang.String}
                  {:key :port :text "PORT" :class java.lang.Long}
                  {:key :comment :text "Comment" :class java.lang.String}])

  (def ds (atom (take 3 datas)))

  (utils/show-ui (http-message-viewer
                  {:datas ds
                   :columns cols-info
                   :setting-key :add-csrf/macro
                   :ac-words (->> (first datas)
                                  keys)
                   :key-fn :index
                   }))

  (def acb (make-ac-combox {:setting-key :csrf-filter
                            :auto-completion {:parameter-assistance? true
                                              :trigger-key "control PERIOD"
                                              :delay 10
                                              :provider {:ac-words ["request"
                                                                    "response"
                                                                    "defn"
                                                                    "reverse"
                                                                    "str/split"
                                                                    "str/reverse"]
                                                         :completions {:basic [{:text "test"}
                                                                               {:text "tencent"
                                                                                :desc "tencent test"
                                                                                :summary "test text"}]}}}
                            :item-validation (fn [txt]
                                               (prn "validate:" txt)
                                               (try (get-filter-pred txt)
                                                    true
                                                    (catch Exception e
                                                      (gui/invoke-later
                                                       (gui/alert
                                                        (format "filter expression: %s"
                                                                txt
                                                                (.getMessage e))))
                                                      false)))}))


  (utils/show-ui acb)

  )
