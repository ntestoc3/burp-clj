(ns burp-clj.filter-exp
  (:require [burp-clj.filter-exp :refer :all]
            [instaparse.core :as insta]
            [clojure.test :refer :all]))

(defn uniq-parse?
  [exp]
  (= 1 (-> (insta/parses filter-exp exp)
           count)))

(testing "filter expr"
  (testing "filter expr parser"
    (is (insta/failure? (filter-exp "test contains 123'")))

    (is (uniq-parse? "test in {1 2, 3 ;  4}"))

    (is (uniq-parse? "resp.header.content-type in {2 3}"))

    (is (uniq-parse? "response.header.content-type"))

    (is (uniq-parse? "!a > 5  && b < 3 || c == 6 && d >= 8"))

    (is (uniq-parse? "! (test > 5)"))

    (is (uniq-parse? "! (test > 5) && (b < 3)"))

    (is (uniq-parse? " (a > 1) && (!(b > 2) || (c > 3)) && (e <= 4)"))

    (is (uniq-parse? "a > 1 && b > 2 && c > 3 && d.e.f || a == 'test' || ee contains \"go.e&&||go\" && ff in {1  ; 2 ; '3',-4.22} "))
    )


  (let [data {:test 123
              :v2 "test content"
              :request.headers/cookie "tcook=1"
              :response/body "response data b2"
              :request/body nil
              :response/length 42
              :port 80}
        filter-data (fn [exp]
                      (->> (filter-exp exp)
                           (eval-pred data)))]
    (is (not (filter-data "test in {1 2  4 \"bb\"}")))

    (is (filter-data "test >= 23"))

    (is (filter-data "test contains '12'"))

    (is (filter-data "!(!port == 80)"))

    (is (filter-data "test > 100 && port > 100 || response.body contains 'data'"))

    (is (filter-data "response.length in {1 8 '15', 42 99}"))

    (is (filter-data "response.length >= 40"))

    (is (filter-data "test == 123 && response.length >= 40"))

    (is (not (filter-data "test < 123 || response.length < 40")))

    (is (filter-data "!(test > 400 || port > 81) && response.length > 5"))

    (is (not (filter-data "request.body")))

    (is (filter-data "port"))

    (is (thrown? NullPointerException
                 (filter-data "request.body > 2")))

    (is (thrown? ClassCastException
                 (filter-data "response.body <= 5")))

    (is (filter-data "request.headers.cookie contains 'cook'"))

    )
  )

