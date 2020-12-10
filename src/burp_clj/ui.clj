(ns burp-clj.ui
  (:require [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.border :as border]
            [seesaw.color :as color]
            [seesaw.icon :as icon]
            [seesaw.dnd :as dnd]
            [seesaw.chooser :refer [choose-file]]
            [clojure.edn :as edn]
            [taoensso.timbre :as log]
            [me.raynes.fs :as fs]
            [burp-clj.state :as state]
            [clojure.java.io :as io]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.options :as opts]
            [burp-clj.extender :as extender]
            [burp-clj.script-table :as script-table]
            [burp-clj.utils :as utils]
            [burp-clj.scripts :as script]
            [burp-clj.i18n :as i18n]
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

(defn choose-dir-btn
  [default-dir target-path]
  (gui/button :icon (io/resource "open_dir.png")
              :text (i18n/ptr :choose-folder)
              :listen [:action (fn [e]
                                 (let [root (gui/to-root e)]
                                   (when-let [path (choose-file root
                                                                :dir default-dir
                                                                :type :open
                                                                :selection-mode :dirs-only)]
                                     (-> (gui/select root target-path)
                                         (gui/text! (str path))))))]))

(defn input-dir
  [{:keys [parent title text default-path]}]
  (let [default-path (when (and default-path
                                (fs/directory? default-path))
                       default-path
                       (str (fs/home)))
        dlg (gui/dialog
             :parent parent
             :title title
             :modal? true
             :content (mig-panel
                       :border (border/empty-border :left 10 :top 10)
                       :items [[text
                                "wrap"]
                               [(gui/text :id :info
                                          :text default-path)
                                "grow, wmin 300"]
                               [(choose-dir-btn default-path [:#info])
                                "gap 5px"]])
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
  (utils/add-dep [])
  (when-some [source (input-dir {:title (i18n/ptr :add-source-dlg/title)
                                 :parent parent
                                 :text (i18n/ptr :add-source-dlg/msg)})]
    (try
      (script/add-script-source! source)
      (catch AssertionError _
        (gui/invoke-later
         (gui/alert (i18n/ptr :add-source-dlg/not-valid source)))))))

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
   :constraints [""
                 "[][fill,grow]"
                 ""
                 ]
   :items [[(make-header {:text (i18n/ptr :script-source-form/header)})
            "span, grow, wrap"]

           [(gui/button :text (i18n/ptr :script-source-form/add)
                        :listen [:action
                                 (fn [e]
                                   (-> (gui/to-root e)
                                       show-add-source-dlg))])
            "growx"]

           [(gui/scrollable (source-list))
            "spany 5, grow, wrap, wmin 300"]

           [(gui/button :text (i18n/ptr :script-source-form/remove)
                        :listen [:action
                                 (fn [e]
                                   (when-let [sel (-> (gui/to-root e)
                                                      (gui/select [:#script-source])
                                                      (gui/selection)
                                                      )]
                                     (log/info "remove script source:" sel)
                                     (script/remove-script-source! sel)))])
            "grow, wrap"]

           [(gui/button :text (i18n/ptr :script-source-form/reload)
                        :listen [:action (fn [e]
                                           (gui/invoke-later
                                            (gui/config! e :enabled? false)
                                            (future
                                              (script/reload-sources!)
                                              (log/info "scripts reload ok!")
                                              (gui/invoke-later
                                               (helper/switch-clojure-plugin-tab)
                                               (gui/config! e :enabled? true)))))])
            "grow,wrap"]
           ]))


(defn proxy-form
  []
  (let [proxy (helper/get-proxy)]
    (mig-panel
     ;; :border (border/empty-border :left 10 :top 10)
     :items [[(gui/checkbox :text (i18n/ptr :http-proxy-form/check-text)
                            :selected? (:enabled proxy)
                            :listen [:action
                                     #(->> (gui/selection %1)
                                           (helper/update-proxy! assoc :enabled))])
              "span, grow, wrap"]

             [(i18n/ptr :http-proxy-form/host)]
             [(gui/text :text (:host proxy)
                        :listen [:document
                                 #(->> (gui/text %)
                                       (helper/update-proxy! assoc :host))])
              "grow, wrap, wmin 200"]

             [(i18n/ptr :http-proxy-form/port)]
             [(gui/text :text (str (:port proxy))
                        :listen [:focus-lost
                                 (fn [e]
                                   (try
                                     (->> (gui/text e)
                                          Integer/parseInt
                                          (helper/update-proxy! assoc :port))
                                     (catch Exception e
                                       (gui/alert e
                                                  (i18n/ptr :http-proxy-form/not-valid-port (gui/text e))
                                                  :type :error)
                                       (gui/invoke-now
                                        (-> (helper/get-proxy)
                                            :port
                                            str
                                            (gui/text! e))))))])
              "grow, wrap"]

             [(i18n/ptr :http-proxy-form/username)]
             [(gui/text :text (:username proxy)
                        :listen [:document
                                 #(->> (gui/text %)
                                       (helper/update-proxy! assoc :username))])
              "grow, wrap"]

             [(i18n/ptr :http-proxy-form/password)]
             [(gui/text :text (:password proxy)
                        :listen [:document
                                 #(->> (gui/text %)
                                       (helper/update-proxy! assoc :password))])
              "grow, wrap"]

             [(i18n/ptr :http-proxy-form/exclusion)]
             [(gui/text :text (:non-proxy-hosts proxy)
                        :tip (i18n/ptr :http-proxy-form/exclusion-tip)
                        :listen [:document
                                 #(->> (gui/text %)
                                       (helper/update-proxy! assoc :non-proxy-hosts))])
              "grow, wrap"]
             ])))

(defn lang-cell [this {:keys [value selected?]}]
  (if value
    (gui/config! this :text (get i18n/supported-lang value))
    (gui/config! this :text "None"))
  (when selected?
    (.setBackground this (color/color "#ffc599"))))

(defn misc-form
  []
  (mig-panel
   :items [[(i18n/ptr :setting-form/select-language)]
           [(let [cb (gui/combobox :id :select-language
                                   :model (keys i18n/supported-lang)
                                   :tip (i18n/ptr :setting-form/select-language-tip)
                                   :selected-item (i18n/get-language)
                                   :listen [:selection (fn [e]
                                                         (-> (gui/selection e)
                                                             (i18n/set-language!)))])]
              ;; HACK burp customizeUiComponent会覆盖cell renderer
              ;;  在组件显示时重新修改cell renderer
              (doto cb
                (utils/add-showing-listener
                 #(gui/config! cb :renderer lang-cell))))
            "grow, wrap"]]))

(comment
  (defn log-comp-info
    [comp info]
    (log/info info
              "showing:" (.isShowing comp)
              "valid:" (.isValid comp)
              "displayable:" (.isDisplayable comp)
              "visible:" (.isVisible comp)))

  (utils/add-showing-listener
   #(log-comp-info cb "cb shoiwng")
   {:once false})

  (utils/add-showing-listener
   #(log-comp-info cb "cb hiding")
   {:once false
    :showing false})

  (utils/add-ancestor-listener
   {:add-cb (fn [e]
              (log-comp-info cb "cb add..."))
    :remove-cb (fn [e]
                 (log-comp-info cb "cb remove..."))
    :move-cb (fn [e]
               (log-comp-info cb "cb move..."))})

  )

(defn setting-form
  []
  (mig-panel
   ;; :border [(border/line-border :thickness 1) 5]
   :items [[(make-header {:text (i18n/ptr :setting-form/header)})
            "span, grow, wrap"]

           [(gui/tabbed-panel
             :tabs [{:title (i18n/ptr :http-proxy-form/header)
                     :content (proxy-form)}

                    {:title (i18n/ptr :setting-form/misc-tab-title)
                     :content (misc-form)}])
            "grow, wrap, wmin 200"]]))

(defn make-view
  []
  (mig-panel
   :border [(border/line-border :thickness 1) 5]
   :constraints [""
                 "[fill,grow]"
                 "[][][][fill,grow]"
                 ]
   :items [[(script-source-form)]

           [(setting-form)
            "span, grow, wrap"]

           [(gui/separator)
            "span, wrap"]

           [(make-header {:text (i18n/ptr :script-list-form/header)})
            "span, wrap"]

           [(script-table/make-table)
            "span, grow"]]))
