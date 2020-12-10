(def feature-version "0.4")
(def build-version "16")
(def release-version (str feature-version "." build-version))
(def project-name "burp-clj")

(defproject project-name feature-version
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [net.portswigger.burp.extender/burp-extender-api "2.1"]
                 [com.cemerick/pomegranate "1.1.0"]
                 [org.tcrawley/dynapath "1.1.0"] ;; dynamic class loader
                 [camel-snake-kebab "0.4.1"]
                 [org.clojure/tools.gitlibs "1.0.83"] ;; git download
                 [cheshire "5.10.0"] ;; json
                 [ntestoc/seesaw "0.1.8"]
                 [version-clj "0.1.2"]
                 [camel-snake-kebab "0.4.2"]
                 [com.github.jarod/qqwry-java "0.8.0"] ;; ip location
                 [me.raynes/fs "1.4.6"]         ;; fs utils
                 [com.taoensso/timbre "4.10.0"] ;; logger
                 [instaparse "1.4.10"]
                 [com.climate/claypoole "1.1.4"] ;; thread pool
                 [diehard "0.10.2"] ;; retry limit
                 [com.rpl/specter "1.1.3"] ;; data manipulation
                 [com.taoensso/tempura "1.2.1"] ;; i18n
                 [org.clojure/core.async "1.3.610"] ;; async
                 ]
  :plugins [[lein-codox "0.10.7"]]
  :codox {:metadata {:doc/format :markdown}}
  :java-source-paths ["java-src"]
  :source-paths ["src"]
  :uberjar-exclusions ["qqwry.dat"]
  :uberjar-name ~(str project-name "-" feature-version ".jar")
  :manifest {"Implementation-Version" ~release-version}
  ;; :omit-source true
  :aot :all
  )
