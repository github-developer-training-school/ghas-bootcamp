/**
 * @name Find System.out.println calls
 * @description Finds all calls to the System.out.println method.
 * Using System.out is generally discouraged in production applications
 * in favour of using a dedicated logging framework.
 * @id java/find-system-out-println
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @tags maintainability
 * convention
 */

import java 

from MethodCall mc // Look at all possible method calls in the code
where
  mc.getMethod().hasName("println") // ...is named "println"
  and
  mc.getMethod().getDeclaringType().hasName("PrintStream")
  and
  mc.getMethod().getDeclaringType().getPackage().hasName("java.io")
  and
  exists(FieldAccess fa | fa = mc.getQualifier() and // Check if the qualifier is a FieldAccess
    fa.getField().hasName("out") and // The field name must be "out"
    fa.getField().getDeclaringType().hasName("System") and // Declared in the "System" class
    fa.getField().getDeclaringType().getPackage().hasName("java.lang") // In the "java.lang" package
  )
select mc, "Avoid using System.out.println(); use a logging framework instead."