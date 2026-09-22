"""P1 restore: staged restore of a trusted backup onto a separate named target.

:mod:`vps3xui.restore.contracts` is the shared contract; :mod:`vps3xui.restore.job`
keeps durable target jobs and their effect journal under the shared host lock,
and :mod:`vps3xui.restore.runtime` bounds stage units. Stage modules are added
by their own backlog tasks against that contract.
"""
