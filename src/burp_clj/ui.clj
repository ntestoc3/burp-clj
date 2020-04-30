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
            [burp-clj.extender :as extender]
            [burp-clj.script-table :as script-table]
            [burp-clj.utils :as utils]
            [burp-clj.scripts :as script]
            [burp-clj.helper :as helper]
            [burp-clj.nrepl :as nrepl]))

(defn make-nrepl-view
  []
  (let [nrepl-port (gui/text :text (str (nrepl/get-port)))
        get-nrepl-btn-txt (fn [started]
                            (if started
                              "stop nREPL"
                              "start nREPL"))
        nrepl-start-stop-btn (gui/button
                              :text (-> (nrepl/started?)
                                        get-nrepl-btn-txt)
                              :id :nrepl-start-stop)
        check-set-nrepl-port (fn []
                               (let [port (gui/text nrepl-port)]
                                 (try
                                   (->> port
                                        Integer/parseInt
                                        nrepl/set-port!)
                                   true
                                   (catch Exception e
                                     (gui/alert e
                                                (str "not valid port: " port)
                                                :type :error)
                                     (gui/invoke-later
                                      (gui/text! nrepl-port (str (nrepl/get-port))))
                                     false))))]
    (bind/bind
     state/state
     (bind/transform #(-> (:nrepl-server %)
                          get-nrepl-btn-txt))
     (bind/property nrepl-start-stop-btn :text))
    (gui/listen nrepl-start-stop-btn
                :action (fn [e]
                          (when (check-set-nrepl-port)
                            (if (:nrepl-server @state/state)
                              (nrepl/stop-nrepl)
                              (nrepl/start-nrepl)))))

    (mig-panel
     :border (border/empty-border :left 10 :top 10)
     :items [
             [(gui/checkbox
               :text "start nrepl server on extension load"
               :selected? (extender/get-setting :nrepl/start-on-load)
               :listen [:selection
                        (fn [e]
                          (->> (gui/selection e)
                               (extender/set-setting! :nrepl/start-on-load)))])
              "span, grow, wrap"]

             ["nrepl version:"]
             [(gui/text :text (nrepl/get-nrepl-version)
                        :listen [:document
                                 #(-> (gui/text %)
                                      nrepl/set-nrepl-version!)])
              "wrap, grow"]

             ["cider-nrepl version:"]
             [(gui/text :text (nrepl/get-cider-version)
                        :listen [:document
                                 #(-> (gui/text %)
                                      nrepl/set-cider-version!)])
              "wrap, grow"]

             ["refactor-nrepl version:"]
             [(gui/text :text (nrepl/get-refactor-version)
                        :listen [:document
                                 #(-> (gui/text %)
                                      nrepl/set-refactor-version!)])
              "wrap, grow"]

             ["server port:"]
             [nrepl-port "wrap, grow, wmin 250,"]

             [nrepl-start-stop-btn "span, grow"]])))

(defn make-header
  [text]
  (gui/label :text text
             :font (seesaw.font/font :name :monospaced
                                     :style :bold
                                     :size 16)
             :foreground :darkorange))

(def burp-img (-> (io/resource "resources/Media/icon32.png" (.getClassLoader burp.ICookie))
                  icon/icon
                  .getImage))

(defn show-add-source-dlg
  [parent]
  (let [dlg (gui/dialog
             :parent parent
             :modal? true
             :content (mig-panel
                       :border (border/empty-border :left 10 :top 10)
                       :items [["Enter script source:"
                                "wrap"]
                               [(gui/text :id :source)
                                "grow, wmin 300"]])
             :option-type :ok-cancel
             :success-fn (fn [p]
                           (-> (gui/to-root p)
                               (gui/select [:#source])
                               (gui/text)
                               (script/add-script-source!))
                           :success))]
    (-> (.getOwner dlg)
        (.setIconImage burp-img))
    (-> dlg
        gui/pack!
        gui/show!)))

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
   :items [[(make-header "Script Source")
            "span, grow, wrap"]

           [(gui/button :text "Add"
                        :listen [:action
                                 (fn [e] (-> (gui/to-root e)
                                             show-add-source-dlg))])
            "grow"]

           [(gui/scrollable (source-list))
            "spany 5, grow, wrap"]

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
                                            (script/reload-sources!)))])
            "grow,wrap"]
           ]))


(defn make-view
  []
  (gui/tabbed-panel :placement :top
                    :overflow :scroll
                    :tabs [{:title "nREPL"
                            :tip "setting nrepl server"
                            :content (make-nrepl-view)}
                           {:title "extension"
                            :tip "manager extensions"
                            :content (mig-panel
                                      :border [(border/line-border :thickness 1) 5]
                                      :constraints [""
                                                    "[fill,grow]"
                                                    "[][][][fill,grow]"
                                                    ]
                                      :items [[(script-source-form)
                                               "span, wrap"]

                                              [(gui/separator)
                                               "span, wrap"]

                                              [(make-header "Scripts List")
                                               "span, wrap"]

                                              [(script-table/make-table)
                                               "span, wrap"]])}]))
