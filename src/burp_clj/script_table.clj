(ns burp-clj.script-table
  (:require [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.table :as table]
            [seesaw.border :as border]
            [burp-clj.state :as state]
            [seesaw.mig :refer [mig-panel]]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]
            [burp-clj.utils :as utils :refer [override-delegate]]
            [burp-clj.scripts :as script]
            [taoensso.timbre :as log])
  (:import javax.swing.table.TableModel))

(def script-cols-info [{:key :running :text "enable" :class java.lang.Boolean}
                       {:key :name :text "name" :class java.lang.String}
                       {:key :version :text "version" :class java.lang.String}
                       ])

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
                info (table/value-at model row)]
            ;; 这里的info已经是修改过的
            (log/info "table model change script:" (:script-key info)
                      "running:" (:running info))
            (if (:running info)
              (script/enable-script! (:script-key info))
              (script/disable-script! (:script-key info))))))))
    (override-delegate TableModel model
      ;; 必须让第一列可编辑，checkbox才起作用
      (isCellEditable [_ row col]
                      (if (= col 0)
                        true
                        false)))))

(defn fix-script-info
  "修正script info，添加key"
  [info]
  (map (fn [[k v]]
         (assoc v :script-key k))
       info))

(defn make-table []
  (let [tbl (gui/table :id :script-table
                       :model (make-scripts-model (-> (script/get-scripts)
                                                      fix-script-info)))]
    (-> (.getTableHeader tbl)
        (.setReorderingAllowed false))
    (bind/bind
     script/db
     (bind/transform (comp make-scripts-model fix-script-info :scripts))
     (bind/property tbl :model))
    (gui/scrollable tbl)))


(comment

  (utils/show-ui (make-table))

  (require '[seesaw.dev :as dev])
  (dev/show-events (gui/table))

  (dev/show-options (gui/table))

 )



