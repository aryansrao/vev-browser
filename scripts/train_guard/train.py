#!/usr/bin/env python3
"""Train the Huma Guard model and export it to ONNX.

Reads the feature CSV produced by the shared Rust extractor (dump_features),
trains a small MLP (13 -> 16 -> 1, ReLU + sigmoid) with plain-numpy gradient
descent + BCE loss, reports precision/recall on a held-out split, and writes
`model.onnx`. tract loads this at runtime, so the browser scores with the same
learned weights.

Usage: train.py features.csv model.onnx
"""
import sys
import numpy as np
import onnx
from onnx import helper, TensorProto, numpy_helper

np.random.seed(7)


def load(path):
    rows = []
    with open(path) as f:
        next(f)  # header
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [float(x) for x in line.split(",")]
            rows.append(parts)
    data = np.array(rows, dtype=np.float32)
    X, y = data[:, :-1], data[:, -1:]
    return X, y


def standardize(X):
    mu = X.mean(0, keepdims=True)
    sd = X.std(0, keepdims=True) + 1e-6
    return mu, sd


def main():
    csv, out = sys.argv[1], sys.argv[2]
    X, y = load(csv)
    n, d = X.shape
    mu, sd = standardize(X)
    Xn = (X - mu) / sd

    # Train/test split.
    idx = np.random.permutation(n)
    cut = int(n * 0.8)
    tr, te = idx[:cut], idx[cut:]
    Xtr, ytr, Xte, yte = Xn[tr], y[tr], Xn[te], y[te]

    H = 16
    W1 = np.random.randn(d, H).astype(np.float32) * np.sqrt(2.0 / d)
    b1 = np.zeros((H,), np.float32)
    W2 = np.random.randn(H, 1).astype(np.float32) * np.sqrt(2.0 / H)
    b2 = np.zeros((1,), np.float32)

    lr, epochs, lam = 0.05, 4000, 1e-4

    def forward(Xb):
        z1 = Xb @ W1 + b1
        a1 = np.maximum(0, z1)
        z2 = a1 @ W2 + b2
        p = 1.0 / (1.0 + np.exp(-z2))
        return z1, a1, z2, p

    m = len(Xtr)
    for e in range(epochs):
        z1, a1, z2, p = forward(Xtr)
        # BCE gradient wrt z2.
        dz2 = (p - ytr) / m
        gW2 = a1.T @ dz2 + lam * W2
        gb2 = dz2.sum(0)
        da1 = dz2 @ W2.T
        dz1 = da1 * (z1 > 0)
        gW1 = Xtr.T @ dz1 + lam * W1
        gb1 = dz1.sum(0)
        W2 -= lr * gW2; b2 -= lr * gb2
        W1 -= lr * gW1; b1 -= lr * gb1

    # Evaluate.
    _, _, _, ptr = forward(Xtr)
    _, _, _, pte = forward(Xte)
    for name, P, Y in [("train", ptr, ytr), ("test", pte, yte)]:
        pred = (P >= 0.5).astype(np.float32)
        tp = float(((pred == 1) & (Y == 1)).sum())
        fp = float(((pred == 1) & (Y == 0)).sum())
        fn = float(((pred == 0) & (Y == 1)).sum())
        prec = tp / (tp + fp + 1e-9)
        rec = tp / (tp + fn + 1e-9)
        acc = float((pred == Y).mean())
        print(f"{name}: acc={acc:.3f} precision={prec:.3f} recall={rec:.3f}", file=sys.stderr)

    # Fold standardization into the first layer so the ONNX takes RAW features:
    #   (x - mu)/sd @ W1 = x @ (W1/sd) - (mu/sd) @ W1
    Ws = (W1 / sd.T).astype(np.float32)
    bs = (b1 - (mu / sd) @ W1).astype(np.float32).reshape(-1)

    inp = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, d])
    outp = helper.make_tensor_value_info("score", TensorProto.FLOAT, [1, 1])
    init = [
        numpy_helper.from_array(Ws, "W1"),
        numpy_helper.from_array(bs, "b1"),
        numpy_helper.from_array(W2.astype(np.float32), "W2"),
        numpy_helper.from_array(b2.astype(np.float32), "b2"),
    ]
    nodes = [
        helper.make_node("Gemm", ["features", "W1", "b1"], ["z1"]),
        helper.make_node("Relu", ["z1"], ["a1"]),
        helper.make_node("Gemm", ["a1", "W2", "b2"], ["z2"]),
        helper.make_node("Sigmoid", ["z2"], ["score"]),
    ]
    graph = helper.make_graph(nodes, "huma_guard", [inp], [outp], init)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 9
    onnx.checker.check_model(model)
    onnx.save(model, out)
    print(f"wrote {out} ({d} features -> {H} -> 1)", file=sys.stderr)


if __name__ == "__main__":
    main()
