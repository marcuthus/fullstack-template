import { NextResponse } from "next/server"
import { ZodError } from "zod"

import { verifyToken } from "@/utils/jwt.util"

export type AuthenticatedUser = {
    id: string
    username?: string
    role?: string
}

/**
 * Erro com status HTTP e mensagem segura para ser exibida ao cliente.
 */
export class HttpError extends Error {
    constructor(
        public readonly status: number,
        message: string
    ) {
        super(message)
        this.name = "HttpError"
    }
}

export async function authMiddleware(
    request: Request,
    options?: { roles?: string[] }
): Promise<{ user: AuthenticatedUser } | NextResponse> {
    const authHeader = request.headers.get("Authorization")

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return NextResponse.json({ message: "Unauthorized" }, { status: 401 })
    }

    const token = authHeader.split(" ")[1]
    const payload = verifyToken(token, "access")

    if (!payload || !payload.sub) {
        return NextResponse.json({ message: "Invalid or expired token" }, { status: 401 })
    }

    if (options?.roles && options.roles.length > 0) {
        if (!payload.role || !options.roles.includes(payload.role)) {
            return NextResponse.json({ message: "Forbidden" }, { status: 403 })
        }
    }

    return {
        user: {
            id: payload.sub,
            username: payload.username,
            role: payload.role,
        },
    }
}

function getPrismaErrorCode(error: unknown) {
    if (typeof error === "object" && error !== null && "code" in error) {
        const code = (error as { code?: unknown }).code
        return typeof code === "string" && code.startsWith("P") ? code : null
    }

    return null
}

export function handleRouteError(error: unknown) {
    if (error instanceof ZodError) {
        return NextResponse.json({ errors: error.issues }, { status: 400 })
    }

    if (error instanceof HttpError) {
        return NextResponse.json({ message: error.message }, { status: error.status })
    }

    switch (getPrismaErrorCode(error)) {
        case "P2002":
            return NextResponse.json({ message: "Conflict" }, { status: 409 })
        case "P2025":
            return NextResponse.json({ message: "Not Found" }, { status: 404 })
    }

    // Erros inesperados (banco, bibliotecas...) não devem ter a mensagem interna exposta ao cliente.
    console.error(error)

    return NextResponse.json({ message: "Internal Server Error" }, { status: 500 })
}
