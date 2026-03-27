import importlib.util, os, sys
import joblib

# Load your existing training script as a module
spec = importlib.util.spec_from_file_location("trainer", "train_from_dataset.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Try to find an IsolationForest instance exposed by the trainer
try:
    from sklearn.ensemble import IsolationForest
except Exception as e:
    print("scikit-learn missing? pip3 install scikit-learn", file=sys.stderr)
    raise

model = None
# Common variable names to check first
for name in ("iso_forest", "model", "IF", "clf", "iforest"):
    obj = getattr(mod, name, None)
    if isinstance(obj, IsolationForest):
        model = obj
        print(f"Found model in variable: {name}")
        break

# Fallback: scan module globals for any IsolationForest
if model is None:
    for name, obj in mod.__dict__.items():
        if isinstance(obj, IsolationForest):
            model = obj
            print(f"Found model by scan: {name}")
            break

if model is None:
    print("❌ Could not find an IsolationForest instance in train_from_dataset.py.\n"
          "   Quick fix: in your trainer, assign your trained model to a top-level variable, e.g.:\n"
          "       iso_forest = IsolationForest(...)\n"
          "   so this saver can find it.", file=sys.stderr)
    sys.exit(2)

os.makedirs("models", exist_ok=True)
out = "models/iso_forest.pkl"
joblib.dump(model, out)
print(f"✅ Saved model to {out}")
