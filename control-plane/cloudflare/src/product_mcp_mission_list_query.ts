/** Bounded read-only mission discovery arguments shared by Device and Project enqueue. */
export const MISSION_LIST_LABEL_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$";
export const MISSION_LIST_MAX_OFFSET = 1000000;
const missionLabel = new RegExp(MISSION_LIST_LABEL_PATTERN, "u");

export function validMissionProcessListQuery(value: Record<string, unknown>): boolean {
  if (!Object.keys(value).every((key) => ["mission_id", "mission_project", "offset"].includes(key))) return false;
  const id = value.mission_id;
  const project = value.mission_project;
  const offset = value.offset;
  if (id !== undefined && (typeof id !== "string" || !missionLabel.test(id))) return false;
  if (project !== undefined && (id === undefined || typeof project !== "string" || !missionLabel.test(project))) return false;
  if (offset !== undefined && (typeof offset !== "number" || !Number.isInteger(offset)
    || offset < 0 || offset > MISSION_LIST_MAX_OFFSET)) return false;
  return true;
}
