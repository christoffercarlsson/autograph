package sh.autograph

internal class Support {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographReady(): Boolean

        fun ready() {
            if (!autographReady()) {
                throw RuntimeException("Initialization failed")
            }
        }
    }
}

public fun ready() {
    return Support.ready()
}
