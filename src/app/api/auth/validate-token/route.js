/**
 * Token Validation Endpoint
 * POST /api/auth/validate-token
 * Validates session token and returns payload
 */

import { NextResponse } from 'next/server';
import { verifyToken, isTokenValid } from '@/core/auth/jwt.utils';
import { isSessionInvalidated } from '@/core/auth/session.service';
import { getPSBSessionCookieFromRequest } from '@/core/auth/cookies.utils';

export async function GET(request) {
  try {
    // Get token from request
    const token = getPSBSessionCookieFromRequest(request);

    if (!token) {
      return NextResponse.json(
        { valid: false, error: 'No session token found' },
        {
          status: 401,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      );
    }

    // Verify token
    let payload;
    try {
      payload = await verifyToken(token);
    } catch (error) {
      return NextResponse.json(
        { valid: false, error: error.message },
        {
          status: 401,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      );
    }

    // Check if token has been invalidated
    const invalidated = await isSessionInvalidated(token);
    if (invalidated) {
      return NextResponse.json(
        { valid: false, error: 'Session has been invalidated' },
        {
          status: 401,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      );
    }

    // Return token payload
    return NextResponse.json(
      {
        valid: true,
        payload: {
          userId: payload.userId,
          email: payload.email,
          fullName: payload.fullName,
          modules: payload.modules || [],
          roles: payload.roles || [],
          issuedAt: payload.issuedAt,
          expiresAt: payload.expiresAt,
        },
      },
      {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true',
        },
      }
    );
  } catch (error) {
    console.error('Token validation error:', error);
    return NextResponse.json(
      { valid: false, error: 'Internal server error' },
      {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true',
        },
      }
    );
  }
}

export async function POST(request) {
  try {
    const body = await request.json();
    const { token } = body;

    if (!token) {
      return NextResponse.json(
        { valid: false, error: 'Token is required' },
        {
          status: 400,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      );
    }

    // Verify token
    let payload;
    try {
      payload = await verifyToken(token);
    } catch (error) {
      return NextResponse.json(
        { valid: false, error: error.message },
        {
          status: 401,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      );
    }

    // Check if token has been invalidated
    const invalidated = await isSessionInvalidated(token);
    if (invalidated) {
      return NextResponse.json(
        { valid: false, error: 'Session has been invalidated' },
        {
          status: 401,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      );
    }

    // Return token payload
    return NextResponse.json(
      {
        valid: true,
        payload: {
          userId: payload.userId,
          email: payload.email,
          fullName: payload.fullName,
          modules: payload.modules || [],
          roles: payload.roles || [],
          issuedAt: payload.issuedAt,
          expiresAt: payload.expiresAt,
        },
      },
      {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true',
        },
      }
    );
  } catch (error) {
    console.error('Token validation error:', error);
    return NextResponse.json(
      { valid: false, error: 'Internal server error' },
      {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true',
        },
      }
    );
  }
}

export async function OPTIONS(request) {
  return NextResponse.json(
    {},
    {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
      },
    }
  );
}
