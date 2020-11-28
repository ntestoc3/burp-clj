(ns burp-clj.table-util
  (:require [seesaw.table :as table]
            [seesaw.core :as gui]))


(defn- filter-table-by
  "返回[[row-index row-value]...]格式的序列"
  [tbl f]
  (->> (table/row-count tbl)
       (range)
       (table/value-at tbl)
       (map-indexed (fn [idx v]
                      [idx (f v)]))
       (filter second)))

(defn insert-by!
  [tbl f value]
  (->>  (filter-table-by tbl f)
        (mapcat #(vector %1 value))
        (apply table/insert-at! tbl)))

(defn update-by!
  [tbl f value]
  (->> (filter-table-by tbl f)
       (mapcat #(vector %1 value))
       (apply table/update-at! tbl)))

(defn remove-by!
  [tbl f]
  (->> (filter-table-by tbl f)
       (map first)
       (apply table/remove-at! tbl)))


