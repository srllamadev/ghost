/**
 * Clear-Sign Modal — shows a human-readable transaction summary before broadcast.
 *
 * Security principle: the user should always know exactly what they're signing.
 * This is especially important for a privacy wallet where addresses are one-time
 * and opaque — we must show the amount and fee clearly.
 */

interface Field {
  label: string;
  value: string;
  mono?: boolean;
}

interface ClearSignModalProps {
  title:       string;
  fields:      Field[];
  warningText: string;
  onConfirm:   () => void | Promise<void>;
  onCancel:    () => void;
}

export default function ClearSignModal({
  title,
  fields,
  warningText,
  onConfirm,
  onCancel,
}: ClearSignModalProps) {
  return (
    <div className="fixed inset-0 bg-black/80 flex items-end justify-center z-50 p-4">
      <div className="bg-gray-900 rounded-3xl w-full max-w-md p-6">
        <h3 className="text-xl font-bold mb-4 text-center text-white">{title}</h3>

        <div className="flex flex-col gap-3 mb-6">
          {fields.map((f, i) => (
            <div key={i} className="bg-gray-800 rounded-xl px-4 py-3">
              <p className="text-gray-500 text-xs mb-1">{f.label}</p>
              <p className={`text-white text-sm break-all ${f.mono ? "font-mono" : ""}`}>
                {f.value}
              </p>
            </div>
          ))}
        </div>

        <div className="bg-yellow-900/30 border border-yellow-700/50 rounded-xl p-3 mb-6 text-xs text-yellow-400 text-center">
          ⚠️ {warningText}
        </div>

        <div className="flex gap-3">
          <button
            className="flex-1 bg-gray-800 hover:bg-gray-700 text-white font-semibold py-4 rounded-2xl"
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            className="flex-1 bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl"
            onClick={onConfirm}
          >
            Confirm & Send
          </button>
        </div>
      </div>
    </div>
  );
}
