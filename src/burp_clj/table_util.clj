(ns burp-clj.table-util
  "table辅助函数"
  (:require [seesaw.table :as table]
            [seesaw.core :as gui]))

(defn- filter-table-by
  "返回[[row-index row-value]...]格式的序列"
  [tbl f]
  (->> (table/row-count tbl)
       (range)
       (table/value-at tbl)
       (map-indexed vector)
       (filter (comp f second))))

(defn insert-by!
  "根据条件查找并插入新行
  filter-pred 过滤函数，参数为table row数据
  value 要插入的数据，格式同`seesaw.table/insert-at!`的value
  after 是否在查找的行之后插入，默认为false"
  ([tbl filter-pred value] (insert-by! tbl filter-pred value false))
  ([tbl filter-pred value after]
   (->>  (filter-table-by tbl filter-pred)
         (mapcat (fn [[idx v]]
                   [(if after
                      (inc idx)
                      idx)
                    value]))
         (apply table/insert-at! tbl))))

(defn update-by!
  "根据条件查找并更新行
  filter-pred 过滤函数，参数为table row数据
  update-fn 更新函数，参数为table row数据
  "
  [tbl filter-pred update-fn]
  (->> (filter-table-by tbl filter-pred)
       (mapcat (fn [[idx v]]
                 [idx (update-fn v)]))
       (apply table/update-at! tbl)))

(defn remove-by!
  "根据条件查找并删除行
  filter-pred 过滤函数，参数为table row数据
  "
  [tbl filter-pred]
  (->> (filter-table-by tbl filter-pred)
       (map first)
       (apply table/remove-at! tbl)))


