(ns burp-clj.filter-exp
  (:require [instaparse.core :as insta]
            [clojure.edn :as edn]
            [clojure.string :as str]))

(def filter-exp
  (insta/parser
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
   ))

(defn eval-pred [obj exp]
  (insta/transform
   {:not not
    :number #(-> (apply str %&)
                 edn/read-string)
    :set #(set %&)
    :obj (fn [& args]
           (let [k (keyword (when (> (count args) 1)
                              (str/join "." (butlast args)))
                            (last args))]
             (get obj k)))
    :le <=
    :lt <
    :ge >=
    :gt >=
    :eq ==
    :neq not=
    :contains str/includes?
    :in (fn [src dst]
          (dst src))
    :and #(and %1 %2)
    :or #(or %1 %2)
    :exp boolean
    }
   exp))

