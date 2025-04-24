/**
 * @name Cross-site scripting
 * @description Directly writing user input to a web page without proper sanitization
 * @id java/xss
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @tags security
 * @tags external/cwe/cwe-079
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.XSS

class ServletParameterSource extends TaintTracking::Source {
  ServletParameterSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getParameter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

from XSS::Sink sink, ServletParameterSource source
where XSS::hasFlow(source, sink)
select sink.getNode(), source, sink,
  "Potential XSS vulnerability: User input is written directly to the response without proper sanitization." 