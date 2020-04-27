package burp;

import clojure.java.api.Clojure;
import clojure.lang.IFn;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());
        IFn require = Clojure.var("clojure.core", "require");
        require.invoke(Clojure.read("burp-clj.core"));
        IFn register = Clojure.var("burp-clj.core", "register");
        register.invoke(callbacks);
    }
}
