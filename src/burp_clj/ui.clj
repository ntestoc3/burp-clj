(ns burp-clj.ui
  (:require [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.border :as border]
            [seesaw.color :as color]
            [seesaw.icon :as icon]
            [seesaw.dnd :as dnd]
            [taoensso.timbre :as log]
            [burp-clj.state :as state]
            [clojure.java.io :as io]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.options :as opts]
            [burp-clj.extender :as extender]
            [burp-clj.script-table :as script-table]
            [burp-clj.utils :as utils]
            [burp-clj.scripts :as script]
            [burp-clj.helper :as helper]))

(defn make-header
  [{:keys [text bold size]
    :or {bold true
         size 16}}]
  (gui/label :text text
             :font (seesaw.font/font :name :monospaced
                                     :style (when bold
                                              :bold)
                                     :size size)
             :foreground "#ff6633"))

(defn conform
  [{:keys [title text type]
    :or {type :warning}}]
  (-> (gui/dialog
       :title title
       :modal? true
       :option-type :ok-cancel
       :content text
       :type type)
      (gui/pack!)
      gui/show!))

(defn input
  [{:keys [parent title text default-text]
    :or {text "input info:"
         title "get info"}}]
  (let [dlg (gui/dialog
             :parent parent
             :title title
             :modal? true
             :content (mig-panel
                       :border (border/empty-border :left 10 :top 10)
                       :items [[text
                                "wrap"]
                               [(gui/text :id :info
                                          :text default-text)
                                "grow, wmin 300"]])
             :option-type :ok-cancel
             :success-fn (fn [p]
                           (-> (gui/to-root p)
                               (gui/select [:#info])
                               (gui/text))))]
    (-> (.getOwner dlg)
        (.setIconImage @utils/burp-img))
    (-> dlg
        gui/pack!
        gui/show!)))

(defn show-add-source-dlg
  [parent]
  (let [source (input {:title "add source info"
                       :parent parent
                       :text "input source target:"})]
    (try
      (script/add-script-source! source)
      (catch AssertionError _
        (gui/invoke-later
         (gui/alert (format "%s not a valid source!" source)))))))

(defn list-with-elem-at-index
  "Given a sequence cur-order and elem-to-move is one of the items
within it, return a vector that has all of the elements in the same
order, except that elem-to-move has been moved to just before the
index new-idx.

Examples:
user=> (def l [\"a\" \"b\" \"c\" \"d\"])
user=> (list-with-elem-at-index l \"b\" 0)
[\"b\" \"a\" \"c\" \"d\"]
user=> (list-with-elem-at-index l \"b\" 1)
[\"a\" \"b\" \"c\" \"d\"]
user=> (list-with-elem-at-index l \"b\" 2)
[\"a\" \"b\" \"c\" \"d\"]
user=> (list-with-elem-at-index l \"b\" 3)
[\"a\" \"c\" \"b\" \"d\"]
user=> (list-with-elem-at-index l \"b\" 4)
[\"a\" \"c\" \"d\" \"b\"]"
  [cur-order elem-to-move new-idx]
  (let [cur-order (vec cur-order)
        cur-idx (.indexOf cur-order elem-to-move)]
    (if (= new-idx cur-idx)
      cur-order
      (if (< new-idx cur-idx)
        (vec (concat (subvec cur-order 0 new-idx)
                     [ elem-to-move ]
                     (subvec cur-order new-idx cur-idx)
                     (subvec cur-order (inc cur-idx))))
        ;; else new-idx > cur-idx
        (vec (concat (subvec cur-order 0 cur-idx)
                     (subvec cur-order (inc cur-idx) new-idx)
                     [ elem-to-move ]
                     (subvec cur-order new-idx)))))))

(defn source-list
  []
  (let [list (gui/listbox :id :script-source
                          :model (script/get-script-sources)
                          :drag-enabled? true
                          :drop-mode :insert
                          :selection-mode :single
                          :transfer-handler
                          (dnd/default-transfer-handler
                           :import [dnd/string-flavor
                                    (fn [{:keys [target data drop? drop-location] :as m}]
                                      (let [sources (script/get-script-sources)]
                                        (when (and drop?
                                                   (:insert? drop-location)
                                                   (:index drop-location)
                                                   ((set sources) data))
                                          (let [new-order (list-with-elem-at-index
                                                           sources
                                                           data
                                                           (:index drop-location))]
                                            (script/set-script-sources new-order)))))]
                           :export {:actions (constantly :copy)
                                    :start (fn [c]
                                             [dnd/string-flavor (gui/selection c)])}))]
    (bind/bind
     script/db
     (bind/transform :source)
     (bind/property list :model))
    list))


(defn script-source-form
  []
  (mig-panel
   ;; :border (border/empty-border :left 10 :top 10)
   :items [[(make-header {:text "Scripts Source"})
            "span, grow, wrap"]

           [(gui/button :text "Add"
                        :listen [:action
                                 (fn [e] (-> (gui/to-root e)
                                             show-add-source-dlg))])
            "grow"]

           [(gui/scrollable (source-list))
            "spany 5, grow, wrap, wmin 500"]

           [(gui/button :text "Remove"
                        :listen [:action
                                 (fn [e]
                                   (when-let [sel (-> (gui/to-root e)
                                                      (gui/select [:#script-source])
                                                      (gui/selection)
                                                      )]
                                     (log/info "remove script source:" sel)
                                     (script/remove-script-source! sel)))])
            "grow, wrap"]

           [(gui/button :text "Reload Scripts!"
                        :listen [:action (fn [e]
                                           (gui/invoke-later
                                            (gui/config! e :enabled? false)
                                            (future (script/reload-sources!)
                                                    (log/info "scripts load ok!")
                                                    (gui/config! e :enabled? true))))])
            "grow,wrap"]
           ]))


(defn make-view
  []
  (mig-panel
   :border [(border/line-border :thickness 1) 5]
   :constraints [""
                 "[fill,grow]"
                 "[][][][fill,grow]"
                 ]
   :items [[(script-source-form)
            "span, grow, wrap"]

           [(gui/separator)
            "span, wrap"]

           [(make-header {:text "Scripts List"})
            "span, wrap"]

           [(script-table/make-table)
            "span, grow"]]))
