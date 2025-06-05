from threading import RLock

# Create a reentrant lock to safely manage concurrent access to printing or shared resources
print_lock = RLock()