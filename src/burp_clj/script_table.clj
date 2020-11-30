(ns burp-clj.script-table
  (:require [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.table :as table]
            [seesaw.border :as border]
            [burp-clj.state :as state]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.swingx :as guix]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]
            [burp-clj.utils :as utils]
            [burp-clj.scripts :as script]
            [burp-clj.i18n :as i18n]
            [taoensso.timbre :as log]
            [burp-clj.table-util :as table-util])
  (:import javax.swing.table.DefaultTableModel))

(def script-cols-info (when-not *compile-files*
                        [{:key :running
                          :text (i18n/ptr :script-list-form/col-enable)
                          :editable true
                          :class Boolean}
                         {:key :name
                          :text (i18n/ptr :script-list-form/col-name)
                          :class String}
                         {:key :version
                          :text (i18n/ptr :script-list-form/col-version)
                          :class String}
                         ]))

(defn make-scripts-model
  [scripts-info]
  (let [model (table/table-model :columns script-cols-info
                                 :rows scripts-info)]
    ;; 绑定修改事件
    (.addTableModelListener
     model
     (utils/table-model-listener
      (fn [e]
        (when (= 0 (.getColumn e))
          (let [row (.getFirstRow e)
                info (table/value-at model row)
                script-info (script/get-script (:script-key info))]
            (when-not (= (:running info)
                         (:running script-info))
              (if (:running info)
                (script/enable-script! (:script-key info))
                (script/disable-script! (:script-key info)))
              (helper/switch-clojure-plugin-tab)))))))
    model))

(defn fix-script-info
  "修正script info，添加key"
  [k info]
  (assoc info :script-key k))

(defn make-table []
  (let [tbl (guix/table-x :id :script-table
                          :popup (gui/popup
                                  :items [(gui/menu-item
                                           :text (i18n/ptr :script-list-form/menu-reload)
                                           :listen [:action (fn [e]
                                                              (let [tbl (-> (gui/to-root e)
                                                                            (gui/select [:#script-table]))
                                                                    row (gui/selection tbl)]
                                                                (when row
                                                                  (-> (table/value-at tbl row)
                                                                      :script-key
                                                                      script/reload-script!))))])])
                          :model (make-scripts-model []))
        unload (atom false)]
    (-> (.getTableHeader tbl)
        (.setReorderingAllowed false))
    (script/reg-scripts-unload-callback #(reset! unload true))
    (script/reg-script-add-callback (fn [k info]
                                      (when-not @unload
                                        (gui/invoke-later
                                         (->> (fix-script-info k info)
                                              (table/add! tbl))))))
    (script/reg-scripts-clear-callback (fn []
                                         (when-not @unload
                                           (gui/invoke-later
                                            (table/clear! tbl)))))
    (script/reg-script-state-change-callback (fn [k info]
                                               (when-not @unload
                                                 (gui/invoke-later
                                                  (table-util/update-by! tbl
                                                                         #(= k (:script-key %1))
                                                                         (fn [_]
                                                                           (fix-script-info k info)))))))
    (gui/scrollable tbl)))


(comment

  (utils/show-ui (make-table))

  (require '[seesaw.dev :as dev])
  (dev/show-events (gui/table))

  (dev/show-options (gui/table))

 )



