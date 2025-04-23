/**
 * @name Potential SQL Injection
 * @description Detects potential SQL injection vulnerabilities through string concatenation
 * @id java/sql-injection
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @tags security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getParameter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("executeQuery") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      sink.asExpr() = ma.getArgument(0)
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential SQL injection vulnerability. User input flows into SQL query without proper sanitization." 