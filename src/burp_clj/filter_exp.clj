(ns burp-clj.filter-exp
  (:refer-clojure :exclude [eval])
  (:require [instaparse.core :as insta :refer [defparser]]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.utils :as utils]))

(def whitespace (insta/parser "whitespace = #'\\s+'"))

(defparser parse
 "exp = exp0 | expop

    (* BEGIN PRECEDENCE *)
    <exp0> = obj | cmp_exp | <'('> exp <')'>

    <expop> = or | and | not

    (* 右侧不添加or,只进行n从左到右生成 *)
    or =  (exp0 | or | and | not) <'||'> (exp0 | and | not)

    and =  (exp0 | and | not) <'&&'> (exp0 | not)

    not = <'!'> exp0

    <cmp_exp> = le | lt | ge | gt | eq | neq | contains | in | matches
    (* END PRECEDENCE *)

    <lcmp> = obj | number
    le = lcmp <'<='> number
    lt = lcmp <'<'> number
    ge = lcmp <'>='> number
    gt = lcmp <'>'> number
    eq = (lcmp | str) <'=='> bases
    neq = (lcmp | str) <'!='> bases
    contains = (obj | str) <'contains'> (obj | str)
    in = (obj | str) <'in'> set
    matches = (obj | str) <'matches'> (obj | str)

    obj = symbol (<'.'> symbol)*

    <symbol> = #'[a-zA-Z]+[a-zA-Z0-9-_]*'
    set = <'{'> bases (<sep> bases)* <'}'>
    sep = #'[\\s,;]\\s*'
    <bases> = str | number
    number = ['-'] #'[0-9]+' ['.' #'[0-9]+']
    <str> = d_str | s_str
    <d_str> = <'\"'> #'[^\"]*' <'\"'>
    <s_str> = <'\\''> #'[^\\']*' <'\\''>
    "
 :auto-whitespace whitespace
 )

(defn cast-compare
  [f-cmp v1 v2]
  (cond
    (or (and (number? v1) (number? v2))
        (and (string? v1) (string? v2)))
    (f-cmp v1 v2)

    (and (string? v1)
         (number? v2))
    (try (f-cmp (edn/read-string v1)
                v2)
         (catch Exception e
           false))

    :else
    false))

(defn ->filter-obj-name [k]
  (if-some [ns (namespace k)]
    (str ns "." (name k))
    (name k)))

(defn ->keyword [obj-paths]
  (keyword (when (> (count obj-paths) 1)
             (str/join "." (butlast obj-paths)))
           (last obj-paths)))

(defn eval [obj exp]
  (insta/transform
   {:not not
    :number #(-> (apply str %&)
                 edn/read-string)
    :set #(set %&)
    :obj (fn [& args]
           (->> (->keyword args)
                (get obj)))
    :le (partial cast-compare <=)
    :lt (partial cast-compare <)
    :ge (partial cast-compare >=)
    :gt (partial cast-compare >)
    :eq (partial cast-compare ==)
    :neq (partial cast-compare not=)
    :contains (fn [s subs]
                (-> (utils/->string s)
                    (str/includes? subs)))
    :matches (fn [s re-s]
               (->> (utils/->string s)
                    (re-matches (re-pattern re-s))))
    :in (fn [src dst]
          (dst src))
    :and #(and %1 %2)
    :or #(or %1 %2)
    :exp boolean
    }
   exp))

(def failed? insta/failure?)

(defn error-msg
  [error & {:keys [html]}]
  (if html
    (with-out-str
      (print (format "<html>Parse error at line %d, column %d:<br/>"
                     (:line error)
                     (:column error)) )
      (print (subs (:text error) 0 (:index error))
             "<font color='red'>"
             (subs (:text error) (:index error))
             "</font>"
             "<br/><br/>")
      (when-some [reson (:reason error)]
        (if (= 1 (count reson))
          (print "Expected:<br/>")
          (print "Expected one of:<br/>"))
        (doseq [r (map :expecting reson)]
          (instaparse.failure/print-reason r)
          (print "<br/>")))
      (print "</html>"))
    (with-out-str
      (instaparse.failure/pprint-failure error))))
